local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()

function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = { openidc = {} }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  self.handler = require("kong.plugins.oidc.handler")()
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_header_add()
  self.module_resty.openidc.authenticate = function(opts)
    return { user = {sub = "sub", email = "ghost@localhost"}, id_token = { sub = "sub", aud = "aud123"} }, false
  end
  local headers = {}
  kong.service.request.set_header = function(name, value) headers[name] = value end

  self.handler:access({ disable_id_token_header = "yes", disable_userinfo_header = "yes",
                        header_names = { "X-Email", "X-Aud"}, header_claims = { "email", "aud" } })
  lu.assertEquals(headers["X-Email"], "ghost@localhost")
  lu.assertEquals(headers["X-Aud"], "aud123")
end


function TestHandler:testExtractAuthorizationHeaderWhenIsPresent()
  ngx.req.raw_header = function()
      return "Content-Type: application/json\r\nAuthorization: Bearer token\r\n"
  end
  
  local authorizationHeader = ngx.req.raw_header():match("[\r\n][Aa]uthorization:%s*(.-)[\r\n]")
  
  -- Assert that the extracted Authorization header is correct
  lu.assertEquals(authorizationHeader, "Bearer token")

  ngx.req.raw_header = function()
    return "Content-Type: application/json\r\nauthorization: Bearer token\r\n"
  end

  local authorizationHeader = ngx.req.raw_header():match("[\r\n][Aa]uthorization:%s*(.-)[\r\n]")

  -- Assert that the extracted Authorization header is correct
  lu.assertEquals(authorizationHeader, "Bearer token")
end

function TestHandler:testExtractAuthorizationHeaderWhenIsNotPresent()
  ngx.req.raw_header = function()
      return "Content-Type: application/json\r\nAuthorizationZ: Bearer token\r\n"
  end
  
  local authorizationHeader = ngx.req.raw_header():match("[\r\n][Aa]uthorization:%s*(.-)[\r\n]")
  
  lu.assertNil(authorizationHeader)
end

lu.run()
