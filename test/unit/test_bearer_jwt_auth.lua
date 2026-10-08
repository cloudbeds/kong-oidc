local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()

local DISCOVERY_ISSUER = "https://oidc"
local ALLOWED_ISSUER = "https://oidc/v1/oauth"
local ALLOWED_AUD = "aud222"

local function json_encode(value)
  local t = type(value)
  if t == "string" then
    return '"' .. value:gsub('[%c"\\]', function(c)
      local escapes = {['"'] = '\\"', ['\\'] = '\\\\'}
      return escapes[c] or string.format('\\u%04x', c:byte())
    end) .. '"'
  elseif t == "number" or t == "boolean" then
    return tostring(value)
  elseif t == "table" then
    if #value > 0 then
      local items = {}
      for _, v in ipairs(value) do
        items[#items + 1] = json_encode(v)
      end
      return "[" .. table.concat(items, ",") .. "]"
    end
    local items = {}
    for k, v in pairs(value) do
      items[#items + 1] = json_encode(tostring(k)) .. ":" .. json_encode(v)
    end
    return "{" .. table.concat(items, ",") .. "}"
  end
  return "null"
end

function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = { openidc = {} }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  ngx.time = os.time
  ngx.now = os.time
  ngx.http_time = os.date
  kong.log.err = function(...)
    local parts = {}
    for i, v in ipairs({...}) do parts[i] = tostring(v) end
    self.logs[#self.logs + 1] = table.concat(parts, " ")
    print("kong.log.err: ", self.logs[#self.logs])
  end
  self.set_headers = {}
  local set_headers = self.set_headers
  kong.service.request.set_header = function(name, value)
    set_headers[name] = value
  end

  require("cjson").encode = json_encode
  ngx.encode_base64 = function(x) return x end

  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.module_resty.openidc.get_discovery_doc = function(opts)
    return { issuer = DISCOVERY_ISSUER }
  end

  self.introspect_calls = 0
  self.module_resty.openidc.introspect = function(opts)
    self.introspect_calls = self.introspect_calls + 1
    return { active = true, sub = "introspected" }
  end

  -- mirrors lua-resty-jwt claim validation: a validator returning false/nil
  -- or raising an error fails the whole verify
  self.module_resty.openidc.bearer_jwt_verify = function(opts, claim_spec)
    local token = self.jwt_token
    for claim, spec in pairs(claim_spec) do
      local ok, valid = pcall(spec, token[claim], claim, token)
      if not ok or not valid then
        return nil, claim .. " invalid"
      end
    end
    return token, nil, "xxx"
  end

  self.handler = require("kong.plugins.oidc.handler")
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

local function valid_token(overrides)
  local token = {
    iss = ALLOWED_ISSUER,
    sub = "sub111",
    aud = { ALLOWED_AUD },
    iat = os.time(),
    exp = os.time() + 3600,
  }
  for k, v in pairs(overrides or {}) do
    token[k] = v
  end
  return token
end

function TestHandler:base_config(overrides)
  local config = {
    bearer_jwt_auth_enable = "yes",
    client_id = "other-client",
    groups_claim = "groups",
    userinfo_header_name = "x-userinfo",
    introspection_endpoint = "https://oidc/introspect",
    bearer_jwt_auth_allowed_auds = { ALLOWED_AUD },
    bearer_jwt_auth_allowed_issuers = { ALLOWED_ISSUER },
  }
  for k, v in pairs(overrides or {}) do
    config[k] = v
  end
  return config
end

function TestHandler:test_bearer_jwt_auth_success()
  self.module_resty.openidc.bearer_jwt_verify = function(opts)
    local token = {
        iss = "https://oidc",
        sub = "sub111",
        aud = "aud222",
        groups = { "users" }
    }
    return token, nil, "xxx"
  end

  self.handler:access({
    bearer_jwt_auth_enable = "yes",
    client_id = "aud222",
    groups_claim = "groups",
    userinfo_header_name = "x-userinfo"
  })
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub111")
  lu.assertEquals(kong.ctx.shared.authenticated_groups, { "users" })
end

function TestHandler:test_bearer_jwt_auth_fail()
  local called_authenticate
  self.module_resty.openidc.bearer_jwt_verify = function(opts)
    return nil, "JWT expired"
  end

  self.module_resty.openidc.authenticate = function(opts)
    called_authenticate = true
    return nil, "error"
  end
  self.handler:access({bearer_jwt_auth_enable = "yes", client_id = "aud222"})
  lu.assertTrue(called_authenticate)
end

function TestHandler:test_allowed_issuer_accepted()
  self.jwt_token = valid_token()
  self.handler:access(self:base_config())
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub111")
  lu.assertEquals(self.introspect_calls, 0)
  local userinfo = self.set_headers["x-userinfo"]
  lu.assertNotNil(userinfo)
  lu.assertStrContains(userinfo, '"sub":"sub111"')
  lu.assertStrContains(userinfo, '"iss":"' .. ALLOWED_ISSUER .. '"')
end

function TestHandler:test_discovery_issuer_accepted()
  self.jwt_token = valid_token({ iss = DISCOVERY_ISSUER })
  self.handler:access(self:base_config({ bearer_jwt_auth_allowed_issuers = nil }))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub111")
  lu.assertEquals(self.introspect_calls, 0)
end

function TestHandler:test_unknown_issuer_falls_back_to_introspection()
  self.jwt_token = valid_token({ iss = "https://evil.example" })
  self.handler:access(self:base_config())
  lu.assertEquals(self.introspect_calls, 1)
end

function TestHandler:test_wrong_aud_falls_back_to_introspection()
  self.jwt_token = valid_token({ aud = { "other-aud" } })
  self.handler:access(self:base_config())
  lu.assertEquals(self.introspect_calls, 1)
end

function TestHandler:test_expired_falls_back_to_introspection()
  self.jwt_token = valid_token({ iat = os.time() - 7200, exp = os.time() - 3600 })
  self.handler:access(self:base_config())
  lu.assertEquals(self.introspect_calls, 1)
end

function TestHandler:test_missing_sub_falls_back_to_introspection()
  local token = valid_token()
  token.sub = nil
  self.jwt_token = token
  self.handler:access(self:base_config())
  lu.assertEquals(self.introspect_calls, 1)
end

function TestHandler:test_missing_iat_falls_back_to_introspection()
  local token = valid_token()
  token.iat = nil
  self.jwt_token = token
  self.handler:access(self:base_config())
  lu.assertEquals(self.introspect_calls, 1)
end

lu.run()
