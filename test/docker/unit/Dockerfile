ARG KONG_BASE_TAG
FROM kong${KONG_BASE_TAG}
USER root

ENV LUA_PATH /usr/local/share/lua/5.1/?.lua;/usr/local/kong-oidc/?.lua
# For lua-cjson
ENV LUA_CPATH /usr/local/lib/lua/5.1/?.so

# Install unzip for luarocks, gcc for lua-cjson
RUN apt update && apt install -y unzip gcc curl

# Rocks are installed from pinned rockspec URLs because the luarocks bundled
# with the Kong base image fails to search the luarocks.org manifest
ARG LUAROCKS=https://luarocks.org/manifests
RUN luarocks install ${LUAROCKS}/hisham/luacov-0.15.0-1.rockspec
RUN luarocks install ${LUAROCKS}/bluebird75/luaunit-3.4-1.rockspec
RUN luarocks install ${LUAROCKS}/openresty/lua-cjson-2.1.0.10-1.rockspec
RUN luarocks install ${LUAROCKS}/daurnimator/luaossl-20220711-0.rockspec OPENSSL_DIR=/usr/local/kong CRYPTO_DIR=/usr/local/kong

# Change openidc version when version in rockspec changes
RUN luarocks install ${LUAROCKS}/cdbattags/lua-resty-jwt-0.2.3-0.rockspec
RUN luarocks install ${LUAROCKS}/hanszandbelt/lua-resty-openidc-1.7.6-3.rockspec

WORKDIR /usr/local/kong-oidc

COPY . .
