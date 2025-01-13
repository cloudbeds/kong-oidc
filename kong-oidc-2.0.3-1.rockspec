package = "kong-oidc"
version = "2.0.3-1"
source = {
    url = "git://github.com/cloudbeds/kong-oidc",
    tag = "2.0.3-1",
    dir = "kong-oidc"
}
description = {
    summary = "A Kong plugin for implementing the OpenID token introspection",
    detailed = [[
        The **Kong OIDC Plugin** is a custom plugin for Kong Gateway that provides OpenID Connect (OIDC) authentication
        and token introspection capabilities.
    ]],
    homepage = "git://github.com/cloudbeds/kong-oidc",
    license = "Apache 2.0"
}
dependencies = {
    "lua-resty-openidc ~> 1.7.6-3",
    "lua-resty-jwt >= 0.2.0"
}
build = {
    type = "builtin",
    modules = {
    ["kong.plugins.oidc.handler"] = "kong/plugins/oidc/handler.lua",
    ["kong.plugins.oidc.schema"] = "kong/plugins/oidc/schema.lua",
    ["kong.plugins.oidc.session"] = "kong/plugins/oidc/session.lua",
    ["kong.plugins.oidc.utils"] = "kong/plugins/oidc/utils.lua"
    }
}
