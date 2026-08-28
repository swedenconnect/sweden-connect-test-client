![Logo](images/sweden-connect.png)

# Sweden Connect Test Client

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

-----

The [sweden-connect-test-client](https://github.com/swedenconnect/sweden-connect-test-client) repository contains the
testing tool that the Sweden Connect team uses when testing SAML Identity Providers and OpenID Providers.

It is a Spring Boot application that acts both as a SAML Service Provider and as an OpenID Connect Relying Party. One
instance may serve any number of SP:s and RP:s, each with its own entity identifier, metadata and keys, and each of
them may be pointed at any Identity Provider or OpenID Provider that the instance knows about.

The point of the tool is control over what is sent and visibility into what comes back. You select one of the
configured clients and one of the providers it may talk to, and the authentication request is presented as a set of
parameters that may be edited freely before the user is sent off for authentication. Nothing forces the request to be
correct, so requests that a compliant client would refuse to build can be produced on purpose, for example unsigned
requests, requests signed with a key that has not been registered, or hand-edited request contents. When the user
comes back, the response is decoded, validated and displayed as it was received.

Anyone is free to use the tool for testing their own Identity Providers and OpenID Providers. The source code is
delivered as is. It is a test tool rather than a product, parts of it deliberately produce non-compliant messages, and
it will contain bugs and rough edges. We do our best to keep it working and correct, but we make no promises about it,
and we cannot offer support.

The tool is deployed in the Sweden Connect test environments:

- [Sweden Connect Sandbox](https://sandbox.swedenconnect.se): [https://testclient.sandbox.swedenconnect.se](https://testclient.sandbox.swedenconnect.se)

- Sweden Connect QA: TBD

## Contents

- [Configuration and Deployment](configuration.md) - How the application is built, run and configured, and the
  complete set of `testclient.*` properties for the SAML and OpenID Connect sides.

-----

Copyright &copy; 2025-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
