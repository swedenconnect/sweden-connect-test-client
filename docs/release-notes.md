![Logo](images/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
### Version 1.0.9

Date: Not yet released

- A bug was fixed where TLS configuration for the service was not picked up when loading OIDC metadata.
- Added the testclient.oidc.rps[].use-jwks-url configuration setting that allows Relying Party keys to be published 
  via jwks_uri instead of having them embedded in the metadata.
- OIDC authentication requests now send PKCE (`code_challenge` with method S256) in the request URL by default.
- A bug was fixed where the `code_challenge` claim of a request object held the code verifier instead of the challenge.
- The OIDC request builder has new "In Request" and "In Request Body" modes, and the scope can differ between the URL
  and the request object.

### Version 1.0.8

Date: 2026-08-28

- First public version.

-----

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
