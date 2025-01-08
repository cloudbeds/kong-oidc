# Kong OIDC Plugin

The **Kong OIDC Plugin** is a custom plugin for Kong Gateway that provides OpenID Connect (OIDC) authentication and token introspection capabilities. It supports validating bearer tokens, introspecting token details, and injecting claims into upstream requests.

---

## Features

- **OIDC Introspection**: Supports introspection of JWT and opaque tokens against an introspection endpoint.
- **Multi-Issuer Support**: Configurable to work with multiple OIDC issuers.
- **Token Expiry Validation**: Rejects expired tokens with appropriate error messages.

---

## Configuration

The plugin can be applied to a **Service** or **Route**. Below is the list of configuration options:

| Parameter                        | Required | Default                   | Description                                                                 |
|----------------------------------|----------|---------------------------|-----------------------------------------------------------------------------|
| `client_id`                      | No       | -                         | The OIDC client ID.                                                        |
| `client_secret`                  | No       | -                         | The OIDC client secret.                                                    |
| `introspection_endpoint`         | No       | -                         | Default introspection endpoint for token validation.                       |
| `introspection_configurations`   | Yes      | -                         | Array of issuer-specific introspection configurations.                     |
| `introspection_cache_ignore`     | No       | `no`                      | Whether to ignore cached introspection responses.                          |
| `realm`                          | No       | `kong`                    | The authentication realm displayed in the `WWW-Authenticate` header.       |
| `validate_scope`                 | No       | `no`                      | Validates that the token includes the required scope.                      |
| `ssl_verify`                     | No       | `no`                      | Whether to verify SSL certificates during introspection.                   |
| `session_secret`                 | No       | -                         | Secret for encrypting session data.                                        |

---

## Example Configuration

Here’s an example configuration using the plugin in `kong.yml`:

```yaml
_format_version: "3.0"
services:
  - name: test-service
    url: http://mockbin.org/request
    routes:
      - name: test-route
        paths:
          - /test
        plugins:
          - name: kong-oidc
            config:
              client_id: test-client #deprecated soon
              client_secret: test-secret #deprecated soon
              introspection_endpoint: https://example.com/introspect #deprecated soon
              introspection_configurations:
                - issuer: "https://example.com"
                  introspection_endpoint: "https://example.com/introspect"
                  client_id: "test-client"
                  client_secret: "test-secret"
```
## Development
### Running Tests
The plugin includes tests written using Kong Pongo. To run tests:

#### Install and set up Pongo.
Run:
```bash
pongo run
```