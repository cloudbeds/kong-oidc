local OidcHandler = {
    VERSION = "1.6.0",
    PRIORITY = 1000,
}
local utils = require("kong.plugins.oidc.utils")
local session = require("kong.plugins.oidc.session")

function OidcHandler:access(config)
  local oidcConfig = utils.get_options(config, ngx)

  session.configure(config)
  handle(oidcConfig)

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response

  if oidcConfig.introspection_endpoint or oidcConfig.introspection_configurations then
    response = introspect(oidcConfig)
  end

  -- Check if introspection was successful and response is valid
  if not response or not response.active then
    kong.log.debug(ngx.ERR, "OIDC introspection failed or token is inactive")
    return kong.response.exit(ngx.HTTP_UNAUTHORIZED, { message = "Unauthorized: Token verification failed" })
  end
end

function introspect(oidcConfig)
  -- Check for Bearer token or bearer-only mode
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local jwt = require("resty.jwt")
    local token = utils.get_bearer_access_token()
    local decoded_token = jwt:load_jwt(token)

    -- Check if token was successfully decoded
    if not decoded_token then
      kong.log.debug("Failed to decode JWT token")
      return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Invalid token")
    end

    -- Check for expiration
    local exp = decoded_token.payload.exp
    if exp and exp < ngx.time() then
      kong.log.debug("Token has expired")
      return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Token has expired")
    end

    -- Extract the issuer and log it
    local issuer = decoded_token.payload.iss
    if not issuer then
      kong.log.debug("Token missing 'iss' claim")
      return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Invalid token (missing 'iss' claim)")
    end

    -- Extract the full URL (including https://) from the issuer
    local url = issuer:match("^(https?://[^/]+)")  -- This captures the full URL including https://
    if not url then
      kong.log.debug("Unable to extract URL from issuer: " .. issuer)
      return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Invalid issuer")
    end
    kong.log.debug("Extracted URL: " .. url)

    -- Retrieve introspection configurations from the list
    local introspection_configurations = oidcConfig.introspection_configurations
    local introspection_config

    -- Loop through the list of introspection configurations and match the issuer
    for _, config in ipairs(introspection_configurations) do
     if config.issuer == url then
       introspection_config = config
       break
     end
    end

    -- Fallback to legacy configuration if no issuer-specific configuration is found
    if not introspection_config then
      if oidcConfig.introspection_endpoint then
        kong.log.debug("Using legacy introspection endpoint for issuer: " .. url)
        introspection_config = {
          introspection_endpoint = oidcConfig.introspection_endpoint,
          client_id = oidcConfig.client_id,
          client_secret = oidcConfig.client_secret,
          introspection_endpoint_auth_method = oidcConfig.introspection_endpoint_auth_method,
          ssl_verify = oidcConfig.ssl_verify
        }
      else
        kong.log.debug("Unsupported issuer: " .. issuer)
        return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Unsupported issuer")
      end
    end

    -- Prepare configuration for introspection
    local temp_oidcConfig = {
      introspection_endpoint = introspection_config.introspection_endpoint,
      client_id = introspection_config.client_id,
      client_secret = introspection_config.client_secret,
      introspection_endpoint_auth_method = introspection_config.introspection_endpoint_auth_method,
      ssl_verify = introspection_config.ssl_verify,
    }

    if not temp_oidcConfig.introspection_endpoint:match("^https://") then
      kong.log.debug("Insecure introspection endpoint: " .. temp_oidcConfig.introspection_endpoint)
      return kong.response.error(ngx.HTTP_INTERNAL_SERVER_ERROR, "Insecure introspection endpoint")
    end

    -- Perform introspection using the configured settings
    local res, err = require("resty.openidc").introspect(temp_oidcConfig)

    -- Handle introspection errors and inactive tokens
    if err or not res or not res.active then
      local error_message = err or "Inactive token"
      kong.log.debug("OIDC introspection failed: " .. error_message)
      return nil
    end

    kong.log.debug("OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end

  return nil
end

return OidcHandler
