local utils = require("kong.plugins.oidc.utils")
local lu = require("luaunit")

TestToken = require("test.unit.mockable_case"):extend()

function TestToken:setUp()
  TestToken.super:setUp()
end

function TestToken:tearDown()
  TestToken.super:tearDown()
end

function TestToken:test_access_token_authorization_missing()
  _G.ngx = {req = {
    get_headers = function() return {} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_missing()
  _G.ngx = {req = {
    get_headers = function() return {"Authorization"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_exists()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Bearer xxx"} end }
  }
  lu.assertTrue(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_case_insensitive()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "bearer xxx"} end }
  }
  lu.assertTrue(utils.has_bearer_access_token())
end

function TestToken:test_access_token_without_scheme()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "xxx"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
  lu.assertEquals(utils.get_authorization_header(), "xxx")
end

function TestToken:test_access_token_bearer_without_token()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Bearer"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_with_trailing_space_only()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Bearer "} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_tab_separated()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Bearer\txxx"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_bearer_tab_then_space()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Bearer\t xxx"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_other_scheme()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = "Basic xxx"} end }
  }
  lu.assertFalse(utils.has_bearer_access_token())
end

function TestToken:test_access_token_multiple_authorization_headers()
  _G.ngx = {req = {
    get_headers = function() return {Authorization = {"Bearer xxx", "Basic yyy"}} end }
  }
  lu.assertTrue(utils.has_bearer_access_token())
end


lu.run()
