![Logo](images/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
### Version 1.0.10

Date: 2026-09-13

- Replaced the `testclient.oidc.federation.logo-path` setting with a generated, per-RP logotype. An RP now opts in
  by declaring `"logo_uri": "<logo>"` in its metadata, which is resolved to `<base-url>/{path-suffix}/logo.svg`.
- Changed the RP JWKS endpoint from `/oidc/rp/jwks?rp={entity-id}` to `/{path-suffix}/jwks`, matching the URL
  pattern used by the other per-RP endpoints. The old endpoint has been removed.

### Version 1.0.9

Date: 2026-09-13

- A bug was fixed where TLS configuration for the service was not picked up when loading OIDC metadata.
- Added the testclient.oidc.rps[].use-jwks-url configuration setting that allows Relying Party keys to be published 
  via jwks_uri instead of having them embedded in the metadata.

### Version 1.0.8

Date: 2026-08-28

- First public version.

-----

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
