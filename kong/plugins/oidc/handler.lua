local OidcHandler = {
  VERSION = "2.0.1",
  PRIORITY = 1000,
}
local utils = require("kong.plugins.oidc.utils")
local session = require("kong.plugins.oidc.session")

function OidcHandler:access(config)

  if not config.introspection_endpoint and not config.introspection_configurations and not type(config.introspection_configurations) == "table" then
    kong.log.debug(ngx.DEBUG, "Cannot parse introspection endpoints configuration")
    kong.response.exit(ngx.HTTP_UNAUTHORIZED, { message = "Configuration error" })
  end

  session.configure(config)
  handle(config)

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(config)
  local response

  if config.introspection_endpoint or config.introspection_configurations then
    response = introspect(config)
  end

  -- Check if introspection was successful and response is valid
  if not response or not response.active then
    kong.log.debug(ngx.ERR, "OIDC introspection failed or token is inactive")
    return kong.response.exit(ngx.HTTP_UNAUTHORIZED, { message = "Unauthorized: Token verification failed" })
  end
end

function introspect(config)
  local token = utils.get_bearer_access_token()
  local jwt = require("resty.jwt")
  local decoded_token = jwt:load_jwt(token)

  -- Check if token was successfully decoded
  if not decoded_token then
    kong.log.debug("Failed to decode JWT token")
    return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Invalid token")
  end

  if token then
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
    local introspection_config

    -- Loop through the list of introspection configurations and match the issuer
    if config.introspection_configurations and type(config.introspection_configurations) == "table" then
      for _, item in ipairs(config.introspection_configurations) do
        if item.issuer == url then
          introspection_config = item
          break
        end
      end
    end

    -- Fallback to legacy configuration if no issuer-specific configuration is found
    if not introspection_config then
      if config.introspection_endpoint then
        kong.log.debug("Using legacy introspection endpoint for issuer: " .. url)
        introspection_config = {
          introspection_endpoint = config.introspection_endpoint,
          client_id = config.client_id,
          client_secret = config.client_secret,
          introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
          ssl_verify = config.ssl_verify
        }
      else
        kong.log.debug("Unsupported issuer: " .. issuer)
        return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Unsupported issuer")
      end
    end

    if not introspection_config.introspection_endpoint:match("^https://") then
      kong.log.debug("Insecure introspection endpoint: " .. introspection_config.introspection_endpoint)
      return kong.response.error(ngx.HTTP_INTERNAL_SERVER_ERROR, "Insecure introspection endpoint")
    end

    -- Check for expiration
    local exp = decoded_token.payload.exp
    if exp and exp < ngx.time() then
      kong.log.debug("Token has expired")
      return kong.response.error(ngx.HTTP_UNAUTHORIZED, "Token has expired")
    end

    -- Perform introspection using the configured settings
    local res, err = require("resty.openidc").introspect(introspection_config)

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
