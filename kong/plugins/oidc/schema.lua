local typedefs = require "kong.db.schema.typedefs"

-- Introspection configuration schema
local introspection_schema = {
  type = "record",
  fields = {
    { issuer = {
      type = "string",
      required = false
    } },
    { introspection_endpoint = {
      type = "string",
      required = false
    } },
    { client_id = {
      type = "string",
      required = false
    } },
    { client_secret = {
      type = "string",
      required = false
    } },
    { auth_method = {
      type = "string",
      default = "client_secret_post",
      required = false
    } },
    { ssl_verify = {
      type = "string",
      default = "yes",
      required = false
    } },
    { introspection_cache_ignore = {
      type = "string",
      default = "no",
      required = false
    } },
  }
}

return {
  name = "kong-oidc",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        { client_id = {
          type = "string",
          required = false
        } },
        { client_secret = {
          type = "string",
          required = false
        } },
        { ssl_verify = {
          type = "string",
          required = false,
          default = "yes"
        } },
        { session_secret = {
          type = "string",
          required = false
        } },
        { introspection_cache_ignore = {
          type = "string",
          required = false,
          default = "no"
        } },
        { introspection_endpoint = {
          type = "string",
          required = false,
          default = "yes"
        } },
        { introspection_endpoint_auth_method = {
          type = "string",
          required = false,
          default = "client_secret_post"
        } },
        -- This is where you define the array of introspection configurations
        { introspection_configurations = {
          type = "array",
          elements = introspection_schema,
          required = false
        } },
      }
    } },
  }
}
