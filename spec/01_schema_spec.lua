local PLUGIN_NAME = "oidc"
local schema_def = require("kong.plugins." .. PLUGIN_NAME .. ".schema")
local v = require("spec.helpers").validate_plugin_config_schema

describe("Plugin: " .. PLUGIN_NAME .. " (schema), ", function()
  it("minimal conf validates", function()
    assert(v({
    }, schema_def))
  end)

  it("full conf validates", function()
    assert(v({
      client_id = "client-id",
      client_secret = "client-secret",
      introspection_configurations = {
        {
          issuer = "https://example.com", -- Define issuer for introspection
          introspection_endpoint = "https://example.com/introspection", -- Provide introspection endpoint
          client_id = "client-id", -- Add client_id for introspection
          client_secret = "client-secret", -- Add client_secret for introspection
          auth_method = "client_secret_post", -- Specify the authorization method for introspection
          ssl_verify = "yes",
          introspection_cache_ignore = "no",
        }
      },
      introspection_endpoint = "https://example.com/introspection", -- Optional field to validate
      introspection_endpoint_auth_method = "sdfdsa",
      introspection_cache_ignore = "no", -- Optional field to validate
      ssl_verify = "no", -- Optional field to validate
      session_secret = "secret", -- Optional field to validate
    }, schema_def))
  end)
end)
