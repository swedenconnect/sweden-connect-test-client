![Logo](images/sweden-connect.png)

# Release Notes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

---

### Version 1.0.12

Date: _not yet released_

- The OIDC Authentication Result also shows `exp`, `iat`, `nbf`, `auth_time` and `updated_at` as a time in UTC.
- New "Token request options" set the client authentication method, parameters and client assertion claims of the
  token request, and "Display Token Request" shows the token request as it was sent.
- A failed token request (any error status, a network error or an unreadable response) is now shown as a token
  endpoint error instead of "error:null Error Description:null".
- The feature for adding values for the Claims-parameter has been re-designed, and a bug making it impossible to set
  both a value and mark the claim as essential has been fixed.
- The row for the Prompt-parameter now takes several values.

### Version 1.0.11

Date: 2026-09-17

- Showing display name when selecting a OP in the list. The same as in SAML
- A problem where the logotype was not displayed in the footer was fixed.
- OIDC sign request and user message fixes: both are sent as JSON objects in the request object, the "Base64-encode"
  setting encodes the messages (and the TBS data) without encoding a value twice, the selected MIME type is sent. 
  Internal settings no longer leak into the request.
- The `signRequest` URL parameter is now a JWT - signed with a selectable key or unsecured, and optionally encrypted.
- An encrypted request object is now a proper nested JWT (`cty: JWT`) holding the signed or unsecured JWT.
- Configurations exported before this version are not guaranteed to import correctly.
- The OIDC authentication request can be sent with GET or POST, using the new "Send AuthnRequest - GET/POST" buttons.
- "View AuthnRequest" shows the header and claims of a signed or unsigned request object.
- New setting `testclient.oidc.rps[].create-entity-configuration` (default `true`) lets an RP stay outside the
  federation. The "View EC" button is renamed "View Entity Configuration".
- UserInfo can be skipped with the new "Call UserInfo automatically" setting, and called from the Authentication
  Result with "Send UserInfo Request", using any access token and GET or POST.


### Version 1.0.10

Date: 2026-09-16

- Replaced the `testclient.oidc.federation.logo-path` setting with a generated, per-RP logotype. An RP now opts in
  by declaring `"logo_uri": "<logo>"` in its metadata, which is resolved to `<base-url>/{path-suffix}/logo.svg`.
- Changed the RP JWKS endpoint from `/oidc/rp/jwks?rp={entity-id}` to `/{path-suffix}/jwks`, matching the URL
  pattern used by the other per-RP endpoints. The old endpoint has been removed.
- OIDC authentication requests now send PKCE (`code_challenge` with method S256) in the request URL by default.
- A bug was fixed where the `code_challenge` claim of a request object held the code verifier instead of the challenge.
- The OIDC request builder has new "In Request" and "In Request Body" modes, and the scope can differ between the URL
  and the request object.

### Version 1.0.9

Date: 2026-09-10

- A bug was fixed where TLS configuration for the service was not picked up when loading OIDC metadata.
- Added the testclient.oidc.rps[].use-jwks-url configuration setting that allows Relying Party keys to be published 
  via jwks_uri instead of having them embedded in the metadata.

### Version 1.0.8

Date: 2026-08-28

- First public version.

-----

Copyright &copy; 2025-2026, [Myndigheten för digital förvaltning - Swedish Agency for Digital Government (DIGG)](http://www.digg.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
