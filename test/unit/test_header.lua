-- Assuming you have LuaUnit installed
local lu = require('luaunit')

-- Define your test class
TestHandler = {}

-- Define the test function
function TestHandler:testExtractAuthorizationHeaderWhenIsPresent()
  -- Mock the ngx.req.raw_header function
  ngx = {
    req = {
      raw_header = function()
        return "Content-Type: application/json\r\nAuthorization: Bearer token\r\n"
      end
    }
  }
  
  -- Extract the Authorization header
  local authorizationHeader = ngx.req.raw_header():match("[\r\n][Aa]uthorization:%s*(.-)[\r\n]")
  
  -- Assert that the extracted Authorization header is correct
  lu.assertEquals(authorizationHeader, "Bearer token")

  -- Mock ngx.req.raw_header again for the second scenario
  ngx.req.raw_header = function()
    return "Content-Type: application/json\r\nauthorization: Bearer token\r\n"
  end

  -- Extract the Authorization header again
  local authorizationHeader = ngx.req.raw_header():match("[\r\n][Aa]uthorization:%s*(.-)[\r\n]")

  -- Assert that the extracted Authorization header is correct
  lu.assertEquals(authorizationHeader, "Bearer token")
end

-- Run the tests
os.exit(lu.LuaUnit.run())
