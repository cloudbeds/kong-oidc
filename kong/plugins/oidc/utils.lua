local cjson = require("cjson")
local constants = require "kong.constants"

local M = {}

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

return M
