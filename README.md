![Logo](docs/images/sweden-connect.png)

# Sweden Connect Test Client

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Sweden Connect SAML Service Provider and OpenID Connect Relying Party for Test

-----

## About

This repository contains a testing tool that the Sweden Connect team uses internally when testing SAML Identity
Providers and OpenID Providers. It is a Spring Boot application that acts both as a SAML Service Provider and as an
OpenID Connect Relying Party, and it exists to exercise the other side of the protocol.

What it does:

- Lets you compile an authentication request in detail. You select one of the configured clients and one of the
  providers it may talk to, and the request is presented as a set of parameters that may be edited freely before
  anything is sent. Nothing forces the request to be correct, so requests that a compliant client would refuse to
  build can be produced on purpose, for example unsigned requests, requests signed with a key that has not been
  registered, or hand-edited request contents. The user is then sent off to the provider for authentication.

- Analyzes the response and displays it. When the user comes back, the response is decoded, its signature and
  contents are validated, and everything is presented as it was received. This is where you see what the provider
  actually delivered, and whether it holds up.

- Publishes SAML SP metadata for every configured SP, and OpenID Federation entity configurations for every configured
  RP.

- Supports OpenID Federation on the consumer side. OpenID Providers are discovered using subordinate listings and
  configured from the metadata handed out by a trust anchor's resolve endpoint, so that they can be tested against
  without any manual configuration.

Anyone is free to use this tool for testing their own Identity Providers and OpenID Providers. Do note that the source
code is delivered as is. It is a test tool rather than a product, parts of it deliberately produce non-compliant
messages, and it may contain bugs and rough edges. We do our best to keep it working and correct, but we make no
promises about it, and we cannot offer support.

### Running deployments

The tool is deployed in the Sweden Connect test environments:

- [Sweden Connect Sandbox](https://sandbox.swedenconnect.se): [https://testclient.sandbox.swedenconnect.se](https://testclient.sandbox.swedenconnect.se)

- Sweden Connect QA: TBD

## Releases

- See [Release notes](docs/release-notes.md).

## Documentation

See [docs/index.md](docs/index.md) for documentation about how the test client is configured and deployed.

-----

Copyright &copy; 2025-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
