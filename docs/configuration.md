![Logo](images/sweden-connect.png)

# Configuration and Deployment

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

-----

The test client is an ordinary Spring Boot application. Everything that it offers is driven from configuration, i.e.,
the SAML SP:s, the OpenID Connect RP:s, the Identity Providers and OpenID Providers that may be tested against, and the
keys that are used. This page describes how the application is built and run, and documents the settings.

All application specific settings live under the `testclient` prefix. Standard Spring Boot settings, such as
`server.port` and `server.ssl.*`, are used as they are and are not repeated here.

## Contents

1. [Building and running](#building-and-running)
2. [The base URL](#the-base-url)
3. [Feature toggles](#feature-toggles)
4. [Credentials](#credentials)
5. [TLS and HTTP settings](#tls-and-http-settings)
6. [SAML settings](#saml-settings)
7. [OpenID Connect settings](#openid-connect-settings)
8. [OpenID Federation settings](#openid-federation-settings)
9. [Complete examples](#complete-examples)

<a name="building-and-running"></a>
## Building and running

The application requires **Java 21**. There is no Maven wrapper in the repository, so a locally installed Maven is
used.

```bash
mvn clean package
```

Artifacts are downloaded from Maven Central and from the Shibboleth Nexus repository, both of which are declared in the
POM. The build runs the tests, the `maven-enforcer-plugin` with the `dependencyConvergence` rule, and JaCoCo. The
coverage report ends up in `target/site/jacoco/index.html`.

To run the application from the sources:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=<indicate your profile>
```

> **A configuration is always required.** The `application.yml` that is bundled with the application only defines the
> credential bundles and `testclient.non-registered-credential`. It does not assign `testclient.base-url`, which is
> mandatory, so the application will fail at startup unless a profile, or an external configuration file, supplies the
> rest of the settings.

### Docker

The [jib-maven-plugin](https://github.com/GoogleContainerTools/jib) is used to build container images.

```bash
mvn jib:dockerBuild@local           # builds the image local/test-client
```

### External configuration

When the application is deployed, the settings are normally supplied from a file outside of the image using the
standard Spring Boot mechanisms, for example:

```bash
java -jar test-client.jar --spring.config.additional-location=file:/opt/testclient/config/
```

<a name="the-base-url"></a>
## The base URL

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.base-url` | The base URL of the application, including protocol, host name, and possibly port and context path. **Required.** | String | - |

Every externally visible URL that the application produces is built from this setting, and never from the incoming
request. It therefore has to be exactly the URL that the browser, the Identity Provider and the OpenID Provider use.
A trailing slash is removed if present.

The following is derived from the base URL and the `path-suffix` of each configured SP and RP:

| URL | Description |
| :--- | :--- |
| `<base-url>/` | The user interface. |
| `<base-url>/saml/acs/{sp-path-suffix}` | The Assertion Consumer Service of a SAML SP. |
| `<base-url>/saml/metadata/{sp-path-suffix}` | The metadata of a SAML SP. |
| `<base-url>/oidc/redirect/{rp-path-suffix}` | The redirect URI of an OIDC RP. |
| `<base-url>/{rp-path-suffix}` | The entity identifier of an OIDC RP. |
| `<base-url>/{rp-path-suffix}/.well-known/openid-federation` | The OpenID Federation entity configuration of an OIDC RP. |

Note that a SAML SP entity identifier is configured explicitly (`entity-id`), whereas an OIDC RP entity identifier
is always the base URL followed by the RP:s `path-suffix`.

<a name="feature-toggles"></a>
## Feature toggles

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.saml.enabled` | Whether the SAML side is enabled. | Boolean | `false` |
| `testclient.oidc.enabled` | Whether the OpenID Connect side is enabled. | Boolean | `false` |
| `testclient.oidc.federation.enabled` | Whether OpenID Federation support is enabled. Requires that OIDC is enabled. | Boolean | `false` |

A protocol that is turned off has no beans at all, and its endpoints are not published. The user interface hides the
corresponding tabs. At least one of the two protocols has to be enabled for the application to be of any use, but
nothing stops both of them from being enabled at the same time, which is the normal setup for a deployed instance.

When SAML is enabled, `testclient.saml.federation` and at least one entry under `testclient.saml.sps` are required.
When OIDC is enabled, at least one entry under `testclient.oidc.rps` is required.

<a name="credentials"></a>
## Credentials

Keys and certificates are handled by the
[credentials-support](https://github.com/swedenconnect/credentials-support) library. Credentials are normally
configured once as *credential bundles* under the `credential.*` prefix and then referenced where they are needed. See
the [credentials-support documentation](https://docs.swedenconnect.se/credentials-support/) for the full set of
options.

The `application.yml` bundled with the application defines a set of test keys, loaded from
`test-client-credentials.jks`, which is included in the JAR:

```yaml
credential:
  bundles:
    keystore:
      test-client:
        location: classpath:test-client-credentials.jks
        password: secret
        type: JKS
    jks:
      ec-nist-p256:
        name: "Test Client EC NIST-P256"
        store-reference: test-client
        key:
          alias: ec-nist-p256
          key-password: secret
      # ... and so on
```

The bundle identifiers that are available out of the box are `ec-nist-p256`, `ec-nist-p384`, `ec-nist-p521`,
`rsa-1024`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `rsa-4096-expired` and `not-registered`. They exist so that the
operator may test how an Identity Provider or OpenID Provider behaves for different key types and sizes, for an
expired certificate, and for a key that has not been registered. **These keys are published in the repository and offer
no protection whatsoever.** A deployment that is exposed to anything but a test federation should configure its own
credentials.

### Global credentials

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.default-credential` | The credential to use for an SP or RP that does not declare a credential of its own. | Credential | - |
| `testclient.non-registered-credential` | A credential that is deliberately not registered anywhere. Used from the user interface to make a request that is signed with a key that the Identity Provider or OpenID Provider does not know about, so that its error handling may be tested. **Required.** | Credential | `bundle: not-registered` (from the bundled `application.yml`) |

A credential is assigned either by referring to a bundle, or by configuring it in place:

```yaml
testclient:
  default-credential:
    bundle: rsa-4096
```

```yaml
testclient:
  default-credential:
    jks:
      name: "Test Client Signing"
      store:
        location: file:/opt/testclient/keys/client.p12
        password: secret
        type: PKCS12
      key:
        alias: signing
```

### Per SP and RP credentials

Every SAML SP and every OIDC RP may declare its own credentials under `credentials`. Each entry is a credential in the
sense described above.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `credentials.signing` | The signing credential. Signs `AuthnRequest` messages, JWT:s and client assertions. | Credential | `testclient.default-credential` |
| `credentials.future-signing` | A signing credential to be used *after* a key rollover. It is published in the SAML SP metadata as an additional signing key, but is not used for signing. | Credential | - (not published) |
| `credentials.encryption` | The encryption credential, i.e., the key that assertions and JWT:s are encrypted for. | Credential | `testclient.default-credential` |
| `credentials.previous-encryption` | The encryption credential that was used *before* a key rollover. Decryption is attempted with this key as well. | Credential | - |
| `credentials.metadata` | The credential used to sign SAML SP metadata and OpenID Federation entity statements. | Credential | `testclient.default-credential`, and if that is not assigned, the signing credential |

Either `credentials.signing` or `testclient.default-credential` must be assigned, and the same holds for
`credentials.encryption`. If neither is present, the application fails at startup.

<a name="tls-and-http-settings"></a>
## TLS and HTTP settings

These settings apply to the outgoing HTTP calls that the application makes, i.e., when downloading SAML metadata, when
invoking the token and UserInfo endpoints of an OpenID Provider, and when talking to federation endpoints. They do not
affect the TLS server settings, which are configured with the standard `server.ssl.*` properties.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.tls.skip-hostname-verification` | Whether TLS host name verification should be skipped. | Boolean | `false` |
| `testclient.tls.trust-bundle` | The name of a Spring [SSL bundle](https://docs.spring.io/spring-boot/reference/features/ssl.html) holding the TLS trust. If assigned, `default-tls-trust` is not used. | String | - |
| `testclient.tls.default-tls-trust` | How TLS trust is determined when no trust bundle is given. `JVM_TRUST` uses the trust configured for the JVM, `TRUST_ALL` accepts any server certificate. | Enum | `JVM_TRUST` |
| `testclient.tls.http-proxy.host` | The HTTP proxy host. Required if `http-proxy` is configured. | String | - |
| `testclient.tls.http-proxy.port` | The HTTP proxy port. Required if `http-proxy` is configured. | Integer | - |
| `testclient.tls.http-proxy.user-name` | The HTTP proxy user name. | String | - |
| `testclient.tls.http-proxy.password` | The HTTP proxy password. | String | - |

`TRUST_ALL` and `skip-hostname-verification` exist because a test client is often pointed at test servers using
self-signed or otherwise unverifiable certificates. Both should be left alone in a deployment that talks to servers
with proper certificates.

<a name="saml-settings"></a>
## SAML settings

The SAML support is built on [opensaml-addons](https://github.com/swedenconnect/opensaml-addons). Each entry under
`testclient.saml.sps` becomes one SAML Service Provider with its own entity identifier, metadata document, keys and
Assertion Consumer Service URL.

### The federation

The Identity Providers that may be tested against are the ones found in the SAML metadata that is downloaded from the
configured sources.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.saml.federation.description` | A textual description of the federation, displayed in the user interface. **Required** when SAML is enabled. | String | - |
| `testclient.saml.federation.source[]` | The metadata sources. At least one is required. | List | - |
| `testclient.saml.federation.source[].metadata-location` | Where the metadata is fetched from. Either a URL, or a file or classpath resource holding a static metadata document. **Required.** | Resource | - |
| `testclient.saml.federation.source[].validation-certificate` | The certificate used to validate the signature of the downloaded metadata. If it is not assigned, **no signature validation is performed**, and a warning is logged. | Certificate | - |
| `testclient.saml.federation.source[].backup-location` | The file where downloaded metadata is cached, so that the application may start even if the metadata source can not be reached. Strongly recommended when the metadata is downloaded over HTTP. Parent directories are created if needed. | File | - |
| `testclient.saml.federation.idp-sorting[]` | Strings that are matched against the entity identifiers of the Identity Providers in order to control the order in which they are listed in the user interface. | List of strings | empty |

If more than one source is configured, they are combined, and the Identity Providers of all of them are made
available. The list of Identity Providers is cached for 10 minutes.

### Metadata settings shared by all SP:s

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.saml.common-metadata.metadata-template` | A metadata document that is used as the template for every SP. The per SP settings are merged into a copy of it. The application bundles a template at `classpath:saml-metadata-template.xml`. | Resource | - (an empty entity descriptor is built) |
| `testclient.saml.common-metadata.default-entity-categories[]` | The entity categories to declare for an SP that does not declare its own. | List of strings | empty |

The `mdui:UIInfo` logotypes of the template are made absolute using the base URL if they are given as paths. If the
template does not declare any logotypes, the logotypes of the application itself are used.

### The Service Providers

Each entry under `testclient.saml.sps` accepts the following.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `entity-id` | The SAML entity identifier of the SP. **Required.** | String | - |
| `description` | A description of the SP, displayed in the user interface. **Required.** | String | - |
| `path-suffix` | The suffix used in the URL:s of this SP, see [The base URL](#the-base-url). Must be unique among the SP:s. **Required.** | String | - |
| `credentials` | The credentials of the SP, see [Credentials](#credentials). | Credentials | `testclient.default-credential` |
| `metadata.entity-categories[]` | The entity categories to declare in the SP metadata. Overrides `common-metadata.default-entity-categories`. | List of strings | the default entity categories |
| `metadata.wants-assertions-signed` | The `WantAssertionsSigned` attribute of the metadata. | Boolean | from the template |
| `metadata.name-id-formats[]` | The `NameIDFormat` elements of the metadata. | List of strings | from the template |
| `metadata.ui-info.display-name[]` | The `mdui:DisplayName` elements. Each entry is a localized string given as `<language-tag>-<text>`, for example `sv-Sweden Connect Test-SP 1`. | List | from the template |
| `metadata.ui-info.description[]` | The `mdui:Description` elements. Same format as above. | List | from the template |
| `metadata.attribute-consuming-services[]` | The `AttributeConsumingService` elements. | List | - |
| `metadata.attribute-consuming-services[].service-name[]` | The service names, as localized strings. **Required.** | List | - |
| `metadata.attribute-consuming-services[].is-default` | Whether this is the default service. At most one entry may be the default. If no entry is marked, the first one is used. | Boolean | see description |
| `metadata.attribute-consuming-services[].requested-attributes[].attribute-name` | The name of a requested attribute, normally an OID. **Required.** | String | - |
| `metadata.attribute-consuming-services[].requested-attributes[].required` | Whether the attribute is required. | Boolean | `false` |

The metadata of an SP is signed with its metadata credential and published at
`<base-url>/saml/metadata/{path-suffix}`, with a validity of seven days.

<a name="openid-connect-settings"></a>
## OpenID Connect settings

Each entry under `testclient.oidc.rps` becomes one Relying Party. The OpenID Providers that may be tested against are
either configured statically under `testclient.oidc.ops`, or discovered using OpenID Federation, see
[OpenID Federation settings](#openid-federation-settings). If an OP is both statically configured and discovered through the
federation, the federation version is used.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `testclient.oidc.openid-fed-authorities[]` | The entity identifiers of the immediate superiors of our RP:s. Published as `authority_hints` in the entity configurations. **Required** when OpenID Federation is enabled. | List of strings | empty |

### The Relying Parties

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `path-suffix` | The suffix used in the URL:s of this RP, see [The base URL](#the-base-url). The entity identifier of the RP is the base URL followed by this suffix. Must be unique among the RP:s. **Required.** | String | - |
| `description` | A description of the RP, displayed in the user interface. **Required.** | String | - |
| `credentials` | The credentials of the RP, see [Credentials](#credentials). | Credentials | `testclient.default-credential` |
| `metadata` | The `openid_relying_party` metadata of the RP, given as a JSON string. **Required.** | String | - |
| `trust-marks[]` | The trust marks that this RP publishes in its entity configuration. If assigned, the trust marks under `testclient.oidc.federation.trust-marks` are not used for this RP. See [Trust marks](#trust-marks). | List | the federation trust marks |

The `metadata` setting is parsed as OpenID Connect client metadata. Two of its members are always set by the
application and can not be assigned in the JSON: the redirection URI, which is
`<base-url>/oidc/redirect/{path-suffix}`, and the JWK set, which is built from the signing credential of the RP.

Note that the back-channel exchange that the test client performs authenticates using `private_key_jwt`, so the
metadata should declare `"token_endpoint_auth_method": "private_key_jwt"`.

```yaml
testclient:
  oidc:
    rps:
      - path-suffix: "testrp1"
        description: "Test OIDC RP 1 - RP for personal identity number authentication"
        metadata: |
          {
            "response_types" : [ "code" ],
            "grant_types" : [ "authorization_code" ],
            "client_name" : "Sweden Connect Test-RP 1",
            "client_name#sv" : "Sweden Connect Test-RP 1",
            "client_name#en" : "Sweden Connect Test RP 1",
            "contacts" : [ "operations@swedenconnect.se" ],
            "organization_name#sv" : "Sweden Connect",
            "organization_name#en" : "Sweden Connect",
            "subject_type" : "pairwise",
            "token_endpoint_auth_method" : "private_key_jwt",
            "require_auth_time": true
          }
        credentials:
          signing:
            bundle: rsa-4096
```

### Statically configured OpenID Providers

An OpenID Provider that is not part of a federation, or that should be available even when OpenID Federation is turned
off, is configured under `testclient.oidc.ops`.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `entity-id` | The entity identifier, i.e., the issuer, of the OP. | String | - |
| `display-name` | The name displayed in the user interface. | String | the entity identifier |
| `description` | A description displayed in the user interface. | String | - |
| `metadata-endpoint` | The URL where the OP publishes its metadata, normally `<entity-id>/.well-known/openid-configuration`. Used to read the endpoints and keys of the OP. | String | - |
| `authorization-endpoint` | The authorization endpoint of the OP. | String | - |
| `token-endpoint` | The token endpoint of the OP. | String | - |
| `user-info-endpoint` | The UserInfo endpoint of the OP. | String | - |

```yaml
testclient:
  oidc:
    ops:
      - entity-id: https://dev.swedenconnect.se/proxy/realms/BankID
        authorization-endpoint: https://dev.swedenconnect.se/proxy/realms/BankID/protocol/openid-connect/auth
        token-endpoint: https://dev.swedenconnect.se/proxy/realms/BankID/protocol/openid-connect/token
        user-info-endpoint: https://dev.swedenconnect.se/proxy/realms/BankID/protocol/openid-connect/userinfo
        metadata-endpoint: https://dev.swedenconnect.se/proxy/realms/BankID/.well-known/openid-configuration
```

<a name="openid-federation-settings"></a>
## OpenID Federation settings

The OpenID Federation support covers four things: publishing entity configurations for our RP:s, publishing the trust
marks that the RP:s have been issued, discovering OpenID Providers using subordinate listings, and configuring those
OpenID Providers from the metadata handed out by a trust anchor.

All settings live under `testclient.oidc.federation` and are only used when
`testclient.oidc.federation.enabled` is `true`.

### Entity configurations

Each configured RP publishes a signed entity configuration (`application/entity-statement+jwt`) at
`<base-url>/{path-suffix}/.well-known/openid-federation`. The statement contains the `openid_relying_party` metadata of
the RP, including `client_registration_types`, the `federation_entity` metadata, the federation keys of the RP, the
configured `authority_hints` and the trust marks. It is signed with the metadata credential of the RP.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `entity-configuration-validity` | The validity of the entity configurations that we publish. | Duration | `24h` |
| `client-registration-types[]` | The `client_registration_types` declared in our RP metadata. | List of strings | `automatic` |
| `organization-number` | The Swedish organization number published as `organization_number` in the RP metadata, unless the RP declares its own. Exactly ten digits, no hyphen. **Required.** | String | - |
| `logo-path` | The path, relative to the base URL, of the logotype published as `logo_uri` in the RP metadata. It is given as a path since the logotype has to be served from the same host as the RP entity identifiers. | String | `/images/logo.svg` |
| `subject-type` | The `subject_type` declared in our RP metadata, unless the RP declares its own. | String | `pairwise` |
| `entity-metadata.organization-name` | The organization name of the `federation_entity` metadata. | String | - |
| `entity-metadata.contacts[]` | The contacts of the `federation_entity` metadata. | List of strings | empty |
| `entity-metadata.homepage-uri` | The homepage URI of the `federation_entity` metadata. | String | - |
| `entity-metadata.policy-uri` | The policy URI of the `federation_entity` metadata. | String | - |
| `entity-metadata.logo-uri` | The logotype URI of the `federation_entity` metadata. | String | - |

### Trust anchors

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `trust-anchors[]` | The trust anchors of the federation(s) that we participate in. At least one is required when federation support is enabled. | List | - |
| `trust-anchors[].entity-id` | The entity identifier of the trust anchor. **Required.** | String | - |
| `trust-anchors[].jwks` | The keys of the trust anchor, normally received out-of-band. Given either as a resource location, for example `classpath:trust-anchor.jwks`, or as the JWK set itself in JSON. If the keys are not assigned, the entity configuration of the trust anchor is downloaded and its self-declared keys are used. That offers no protection against a rogue trust anchor and a warning is logged, so it should only be used in test setups. | JWK set | - |
| `trust-anchors[].resolve-endpoint` | The resolve endpoint of the trust anchor. Normally not assigned, since it is read from the `federation_entity` metadata of the trust anchor. Assign it if the trust anchor does not publish its entity configuration at its entity identifier, or if it advertises an endpoint that can not be reached from here. Resolve responses are always verified against the trust anchor keys. | URI | from the entity configuration |
| `trust-anchors[].discover-ops` | Whether OpenID Providers should be discovered under this trust anchor. | Boolean | `true` |
| `trust-anchors[].subordinate-listing-sources[]` | The authorities whose subordinate listing endpoints are invoked when discovering OP:s. If not assigned, the discovery starts at the trust anchor itself, i.e., the entire tree below it is traversed. Pointing out one or more intermediates limits the discovery to the parts of the federation where OP:s are registered. A discovered OP is always resolved against the trust anchor. | List | the trust anchor itself |
| `trust-anchors[].subordinate-listing-sources[].entity-id` | The entity identifier of the authority. **Required.** | String | - |
| `trust-anchors[].subordinate-listing-sources[].list-endpoint` | The subordinate listing endpoint of the authority. Normally not assigned, since it is read from the `federation_entity` metadata of the authority. | URI | from the entity configuration |

### Discovering and configuring OpenID Providers

An OpenID Provider is configured by invoking the `federation_resolve_endpoint` of a trust anchor. The trust anchor
builds and validates the trust chain and applies the metadata policies, and returns the resolved metadata in a signed
resolve response. We validate that response, i.e., it must be signed by the trust anchor, be issued about the entity we
asked for, and not have expired, and then use the metadata to configure the endpoints and keys of the OP. No user
interaction is involved.

The resolution is deliberately delegated to the trust anchor rather than performed locally. A local resolver has to
walk the chain bottom-up using `authority_hints`, which fails as soon as an intermediate does not declare its
superiors. The trust anchor knows its own subordinates and can build the chain top-down.

An OP that has once been configured is never removed. If a later refresh can not resolve it, or if the federation
stops listing it, the configuration from the last successful resolution is kept and the OP is reported as
*Resolve failed* or *Not listed* along with the reason. A misbehaving OP, or trust anchor, therefore does not make an
OP disappear from the test client.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `auto-configure-ops` | Whether OP:s should be discovered and configured automatically. | Boolean | `true` |
| `refresh-interval` | How often the federation is traversed in order to discover, and re-configure, OP:s. | Duration | `10m` |
| `max-listing-depth` | How many intermediate levels that are traversed when listing subordinates. | Integer | `5` |

<a name="trust-marks"></a>
### Trust marks

A trust mark is either configured with its value, i.e., a pre-issued trust mark JWT received out-of-band, or fetched
from the trust mark endpoint of its issuer using
`GET <federation_trust_mark_endpoint>?sub=<rp-entity-id>&trust_mark_type=<trust-mark-type>`.

A fetched trust mark is validated before it is published. It must be a `trust-mark+jwt` signed by the issuer, using the
keys of the issuer's entity configuration, be issued about the RP, be of the requested trust mark type, and not have
expired. It is then cached until it expires, and at most for `trust-mark-refresh-interval`. If a trust mark can not be
obtained, the entity configuration is published without it, unless the trust mark is declared as `required`, in which
case no entity configuration is published at all for that RP.

| Property | Description | Type | Default value |
| :--- | :--- | :--- | :--- |
| `trust-marks[]` | The trust marks published in the entity configurations of our RP:s. An RP may declare its own list under `testclient.oidc.rps[].trust-marks`, and in that case this list is not used for that RP. | List | empty |
| `trust-marks[].trust-mark-type` | The trust mark type, i.e., the identifier of the trust mark. Named `id` in the OpenID Federation drafts that preceded 1.0. **Required.** | String | - |
| `trust-marks[].issuer` | The entity identifier of the trust mark issuer. **Required**, unless `value` is given. | String | - |
| `trust-marks[].trust-mark-endpoint` | The trust mark endpoint of the issuer. Normally not assigned, since it is read from the `federation_entity` metadata of the issuer. | URI | from the entity configuration |
| `trust-marks[].value` | A pre-issued trust mark, i.e., a signed JWT received out-of-band. If assigned, the trust mark is published as it is and nothing is fetched from the issuer. | String | - |
| `trust-marks[].required` | Whether the trust mark is required. If a required trust mark can not be obtained, no entity configuration is published for the RP. | Boolean | `false` |
| `trust-mark-refresh-interval` | How long a fetched trust mark is used before it is fetched again. A trust mark that expires before this interval has passed is re-fetched when it expires. | Duration | `1h` |

The trust marks are published with the trust mark type both as `trust_mark_type`, which is what OpenID Federation 1.0
uses, and as `id`, which is what the drafts that preceded it used. The Sweden Connect federation services read the
`trust_marks` of an entity configuration using the Nimbus `TrustMarkEntry`, which requires `id`, whereas the trust
marks themselves and the resolve responses use `trust_mark_type`. Publishing both names means that all of them
understand the entry.

### Federation endpoints

| Endpoint | Description |
| :--- | :--- |
| `GET /{rp-path-suffix}/.well-known/openid-federation` | The entity configuration of an RP. |
| `GET /oidc/federation/info` | Our federation entities, including their trust marks, the trust anchors, and the status of the OP:s discovered from the federation. |
| `POST /oidc/federation/trust-marks/refresh` | Discards the cached trust marks and entity configurations, so that the trust marks are fetched from their issuers again. |
| `POST /oidc/federation/refresh` | Re-runs the discovery and resolution of the federation OP:s. This also happens automatically at `refresh-interval`. |
| `GET /oidc/federation/chain?entity_id=&trust_anchor=` | The trust chain of an entity, as reported by the trust anchor, both serialized and decoded. |
| `GET /oidc/federation/entity-configuration?entity_id=` | The entity configuration of an entity, ours or a remote one. |

<a name="complete-examples"></a>
## Complete examples

### A SAML only setup

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: file:/opt/testclient/keys/tls.p12
    key-store-password: secret
    key-store-type: PKCS12
    key-alias: tls

testclient:
  base-url: https://testclient.example.com
  default-credential:
    bundle: rsa-4096
  saml:
    enabled: true
    federation:
      description: "Sweden Connect Sandbox Federation"
      source:
        - metadata-location: https://md.sandbox.swedenconnect.se/role/idp.xml
          validation-certificate: file:/opt/testclient/metadata/sandbox.crt
          backup-location: /opt/testclient/cache/metadata.xml
    common-metadata:
      metadata-template: classpath:saml-metadata-template.xml
      default-entity-categories:
        - http://id.elegnamnden.se/ec/1.0/loa3-pnr
        - http://id.elegnamnden.se/st/1.0/public-sector-sp
    sps:
      - entity-id: https://testclient.example.com/testsp1
        description: "Test SP 1 - SP for personal identity number authentication"
        path-suffix: "1"
        metadata:
          name-id-formats:
            - urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
          wants-assertions-signed: true
          ui-info:
            display-name:
              - "sv-Sweden Connect Test-SP 1"
              - "en-Sweden Connect Test SP 1"
          attribute-consuming-services:
            - service-name:
                - "sv-Personnummerlegitimering"
                - "en-Authentication using personal identity number"
              requested-attributes:
                - attribute-name: urn:oid:1.2.752.29.4.13
                  required: true
        credentials:
          signing:
            bundle: ec-nist-p256
  oidc:
    enabled: false
```

### An OpenID Connect setup with federation support

```yaml
testclient:
  base-url: https://testclient.example.com
  default-credential:
    bundle: rsa-4096
  saml:
    enabled: false
  oidc:
    enabled: true
    openid-fed-authorities:
      - https://intermediate.example.com
    federation:
      enabled: true
      trust-anchors:
        - entity-id: https://ta.example.com
          jwks: file:/opt/testclient/keys/trust-anchor.jwks
          subordinate-listing-sources:
            - entity-id: https://intermediate.example.com
      auto-configure-ops: true
      refresh-interval: 10m
      organization-number: "2021006883"
      subject-type: pairwise
      entity-metadata:
        organization-name: "Sweden Connect"
        contacts:
          - operations@swedenconnect.se
      trust-marks:
        - trust-mark-type: https://tmi.example.com/trust-mark/test-sp
          issuer: https://tmi.example.com
          required: false
    rps:
      - path-suffix: "testrp1"
        description: "Test OIDC RP 1"
        metadata: |
          {
            "response_types" : [ "code" ],
            "grant_types" : [ "authorization_code" ],
            "client_name" : "Sweden Connect Test-RP 1",
            "subject_type" : "pairwise",
            "token_endpoint_auth_method" : "private_key_jwt"
          }
        credentials:
          signing:
            bundle: rsa-4096
```

-----

Copyright &copy; 2025-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
