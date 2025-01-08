local typedefs = require "kong.db.schema.typedefs"

return {
  name = "kong-oidc",
  fields = {
    {
      -- this plugin will only be applied to Services or Routes
      consumer = typedefs.no_consumer
    },
    {
      -- this plugin will only run within Nginx HTTP module
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          {
            client_id = {
              type = "string",
              required = true
            }
          },
          {
            client_secret = {
              type = "string",
              required = true
            }
          },
          -- List of introspection configurations, each with its own settings
          { introspection_configurations = {
              type = "array",
              elements = {
                type = "record",
                fields = {
                  { issuer = { type = "string", required = false } },
                  { introspection_endpoint = { type = "string", required = false } },
                  { client_id = { type = "string", required = false } },
                  { client_secret = { type = "string", required = false } },
                  { auth_method = { type = "string", default = "client_secret_post", required = false } },
                  { ssl_verify = { type = "string", default = "yes", required = false } },
                  { introspection_cache_ignore = { type = "string", default = "no", required = false } }
                }
              },
              required = false
            }
          },
          {
            introspection_endpoint = {
              type = "string",
              required = false
            }
          },
          {
            introspection_endpoint_auth_method = {
              type = "string",
              required = false,
              default = "client_secret_post"
            }
          },
          {
            introspection_cache_ignore = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            timeout = {
              type = "number",
              required = false
            }
          },
          {
            ssl_verify = {
              type = "string",
              required = true,
              default = "yes"
            }
          },
          {
            session_secret = {
              type = "string",
              required = false
            }
          }
        }
      }
    }
  }
}
