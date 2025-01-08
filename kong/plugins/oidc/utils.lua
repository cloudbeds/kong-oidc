local cjson = require("cjson")
local constants = require "kong.constants"

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) and (not (csvFilters == ",")) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_options(config, ngx)
  -- Extract introspection configurations from the list
  local introspection_configurations = {}

  -- If introspection configurations are provided as a list, loop over them and store them in a table
  if config.introspection_configurations then
    for _, introspection_config in ipairs(config.introspection_configurations) do
      -- Append each introspection configuration (issuer, introspection endpoint, etc.)
      table.insert(introspection_configurations, {
        issuer = introspection_config.issuer,
        introspection_endpoint = introspection_config.introspection_endpoint,
        client_id = introspection_config.client_id,
        client_secret = introspection_config.client_secret,
        auth_method = introspection_config.auth_method or "client_secret_post", -- Default value
        ssl_verify = introspection_config.ssl_verify,
        introspection_cache_ignore = introspection_config.introspection_cache_ignore,
        timeout = introspection_config.timeout,
      })
    end
  end

  -- Return the config with introspection configurations handled
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    introspection_endpoint = config.introspection_endpoint,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    introspection_cache_ignore = config.introspection_cache_ignore,
    introspection_configurations = introspection_configurations,
    timeout = config.timeout,
    ssl_verify = config.ssl_verify
  }
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

-- Function to get the Bearer token from the Authorization header
function M.get_bearer_access_token()
  -- Get the Authorization header
  local header = ngx.req.get_headers()['Authorization']

  -- Check if the header exists and contains a space (indicating a token might follow)
  if header and header:find(" ") then
    local divider = header:find(' ')

    -- Check if the header starts with "Bearer" (case-insensitive)
    if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
      -- Return the token after the space
      return header:sub(divider + 1)
    end
  end
  -- Return nil if no valid Bearer token is found
  return nil
end

-- sanitize oidc config for debugging output
function M.sanitize_oidc_config(config)
  local sanitized = {}
  for k, v in pairs(config) do
    if k == "client_id" or k == "client_secret" then
      sanitized[k] = "<hidden>"
    else
      sanitized[k] = v
    end
  end
  return sanitized
end

return M
