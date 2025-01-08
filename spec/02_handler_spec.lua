local PLUGIN_NAME = "oidc"
local helpers = require "spec.helpers"
local cjson = require "cjson"
local jwt = require "resty.jwt"
local http_mock = require("spec.helpers.http_mock")

local function generate_jwt(payload, secret)
  local token = jwt:sign(
    secret,
    {
      header = { typ = "JWT", alg = "HS256" },
      payload = payload,
    }
  )
  return token
end

-- Define introspection logic in a function
local function introspect_token()
  ngx.header.content_type = "application/json"
  ngx.say(cjson.encode({
    active = true,
    sub = "1234567890",
    exp = ngx.time() + 3600, -- token expiration in 1 hour
  }))
  ngx.exit(ngx.OK)
end

for _, strategy in helpers.each_strategy() do
  describe("Plugin: " .. PLUGIN_NAME .. " (access) [#" .. strategy .. "]", function()
    local client
    local mock, mock_port

    lazy_setup(function()
      mock, mock_port = assert(http_mock.new(nil, {
        ["/introspect"] = {
          access = [[
            local cjson = require("cjson")

            -- Construct the JSON response
            local response = {
              active = true,
              sub = "1234567890",
              exp = ngx.time() + 3600 -- Expiration time, 1 hour from now
            }

            -- Set the content type to JSON
            ngx.header.content_type = "application/json"

            -- Output the JSON response
            ngx.print(cjson.encode(response))
            ngx.exit(200)
          ]]
        },
      }, {
        tls = true,
        gen_client = true,
        log_opts = {
          resp = true,
          resp_body = true
        }
      }))

      assert(mock:start())

      local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })

      -- Add a service and route
      local service = bp.services:insert({
        name = "test-service",
        url = "http://httpbin.org"
      })

      local route = bp.routes:insert({
        hosts = { "test1.com" },
        service = service,
      })

      local legacy_route = bp.routes:insert({
        hosts = { "test2.com" },
        service = service,
      })

      -- Add the plugin with new config
      bp.plugins:insert({
        name = PLUGIN_NAME,
        route = { id = route.id },
        config = {
          client_id = "test-client-id",
          client_secret = "test-client-secret",
          ssl_verify = "no",
          introspection_configurations = {
            {
              issuer = "https://auth.example.com",
              introspection_endpoint = "https://auth.example.com/introspect",
              client_id = "test-client-id",
              client_secret = "test-client-secret",
            },
            {
              issuer = "https://auth2.example.com",
              introspection_endpoint = "https://auth.example.com/introspect",
              client_id = "test-client-id",
              client_secret = "test-client-secret",
            },
            {
              issuer = "https://insecure.example.com",
              introspection_endpoint = "http://auth.example.com/introspect",
              client_id = "test-client-id",
              client_secret = "test-client-secret",
            },
            {
              issuer = "https://mock.example.com",
              introspection_endpoint = "https://localhost:" .. mock_port .. "/introspect",
              client_id = "test-client-id",
              client_secret = "test-client-secret",
              ssl_verify = "no",
            }
          }
        },
      })

      -- Add the plugin with legacy config
      bp.plugins:insert({
        name = PLUGIN_NAME,
        route = { id = legacy_route.id },
        config = {
          client_id = "test-client-id",
          client_secret = "test-client-secret",
          ssl_verify = "no",
          introspection_endpoint = "https://localhost:" .. mock_port .. "/introspect"
        },
      })

      -- Start Kong
      assert(helpers.start_kong({
        database = strategy,
        plugins = "bundled," .. PLUGIN_NAME,
        KONG_LOG_LEVEL = "debug",
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
      if mock then
        mock:stop()
      end
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      mock:clean()
      if client then
        client:close()
      end
      mock.client = nil
    end)

    describe("Token Introspection", function()
      it("returns 401 for a missing token", function()
        local res = assert(client:send({
          method = "GET",
          path = "/get",
          headers = {
            ["Host"] = "test1.com",
          },
        }))
        assert.response(res).has.status(401)
        local body = assert.response(res).has.jsonbody()
        assert.equal("Unauthorized: Token verification failed", body.message)
      end)

      it("returns 401 for an expired token", function()
        -- Mock an expired token
        local token = generate_jwt(
          { sub = "1234567890", name = "Test User", iss = "https://auth.example.com", exp = ngx.time() - 3600 },
          "test-secret"
        )

        local res = assert(client:send({
          method = "GET",
          path = "/get",
          headers = {
            ["Host"] = "test1.com",
            ["Authorization"] = "Bearer " .. token,
          },
        }))
        assert.response(res).has.status(401)
        local body = assert.response(res).has.jsonbody()
        assert.equal("Token has expired", body.message)
      end)

      it("returns 401 for a token with a missing issuer", function()
        -- Mock a token with a missing issuer
        local token = generate_jwt(
          { sub = "1234567890", name = "Test User", exp = ngx.time() + 3600 },
          "test-secret"
        )

        local res = assert(client:send({
          method = "GET",
          path = "/get",
          headers = {
            ["Host"] = "test1.com",
            ["Authorization"] = "Bearer " .. token,
          },
        }))
        assert.response(res).has.status(401)
        local body = assert.response(res).has.jsonbody()
        assert.equal("Invalid token (missing 'iss' claim)", body.message)
      end)

      it("returns 500 for insecure introspection endpoints", function()
        -- Mock a token with an insecure introspection endpoint
        local token = generate_jwt(
          { sub = "1234567890", name = "Test User", iss = "https://insecure.example.com", exp = ngx.time() + 3600 },
          "test-secret"
        )
        local res = assert(client:send({
          method = "GET",
          path = "/get",
          headers = {
            ["Host"] = "test1.com",
            ["Authorization"] = "Bearer " .. token,
          },
        }))
        assert.response(res).has.status(500)
        local body = assert.response(res).has.jsonbody()
        assert.equal("Insecure introspection endpoint", body.message)
      end)
    end)

    describe("Integration: Introspection over HTTPS", function()
      it("returns 200 for a valid token", function()

        -- Generate a valid JWT
        local token = generate_jwt(
          { sub = "1234567890", name = "Test User", iss = "https://mock.example.com", exp = ngx.time() + 3600 },
          "test-secret"
        )

        -- Send request to Kong route
        local res = assert(client:send({
          method = "GET",
          path = "/get",
          headers = {
            ["Host"] = "test1.com",
            ["Authorization"] = "Bearer " .. token,
          },
        }))

        assert.response(res).has.status(200)
        local body = assert.response(res).has.jsonbody()
        assert.is_nil(body.message) -- Plugin should allow the request
      end)

      describe("Integration: Legacy Introspection over HTTPS", function()
        it("returns 200 for a valid token", function()

          -- Generate a valid JWT
          local token = generate_jwt(
            { sub = "1234567890", name = "Test User", iss = "https://mock.example.com", exp = ngx.time() + 3600 },
            "test-secret"
          )

          -- Send request to Kong route
          local res = assert(client:send({
            method = "GET",
            path = "/get",
            headers = {
              ["Host"] = "test2.com",
              ["Authorization"] = "Bearer " .. token,
            },
          }))

          assert.response(res).has.status(200)
          local body = assert.response(res).has.jsonbody()
          assert.is_nil(body.message) -- Plugin should allow the request
        end)

      end)
    end)
  end)
end
