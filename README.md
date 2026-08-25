![Logo](https://raw.githubusercontent.com/swedenconnect/technical-framework/master/img/sweden-connect.png)

# Sweden Connect Test Client

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

Sweden Connect SAML Test SP and OIDC Test RP

---

> TODO

## OpenID Federation

The test client can act as an OpenID Federation entity. The support covers three things:

**1. Publishing entity configurations**

Each configured OIDC RP publishes a signed entity configuration (`application/entity-statement+jwt`) at
`<rp-entity-id>/.well-known/openid-federation`, i.e., at `<base-url>/<path-suffix>/.well-known/openid-federation`.
The statement contains the RP's `openid_relying_party` metadata (including `client_registration_types`), optional
`federation_entity` metadata, the RP's federation keys and the configured `authority_hints`. It is signed with the
RP's metadata credential (`credentials.metadata`, falling back to the default/signing credential).

The trust marks that the RP:s have been issued are published in the `trust_marks` claim (see below).

**2. Listing subordinates**

The OP discovery invokes the subordinate listing endpoint of a trust anchor (or an intermediate), filtered on
`openid_provider`.

The discovery normally starts at the trust anchor and traverses the entire federation tree below it.
By assigning `subordinate-listing-sources` for a trust anchor, the listings are instead made towards the given
authorities (typically the intermediates where the OP:s are registered).

**3. Trust marks**

Each RP that is exposed in the federation may publish trust marks. A trust mark is either configured with its value
(a pre-issued trust mark JWT), or fetched from the trust mark endpoint of its issuer -
`GET <federation_trust_mark_endpoint>?sub=<rp-entity-id>&trust_mark_type=<trust-mark-type>`. The endpoint is read
from the `federation_entity` metadata of the issuer's entity configuration unless it has been configured.

A fetched trust mark is validated - it must be a `trust-mark+jwt` signed by the issuer (using the keys of its entity
configuration), be issued about the RP, be of the requested trust mark type and not have expired - before it is
published. It is then cached until it expires, and at most for `trust-mark-refresh-interval`. If a trust mark can not
be obtained, the entity configuration is published without it, unless the trust mark has been declared as `required`
- in that case no entity configuration is published at all.

The trust marks are published with the trust mark type both as `trust_mark_type` (OpenID Federation 1.0) and as `id`
(the drafts that preceded it). The Sweden Connect federation services read the `trust_marks` of an entity
configuration using the Nimbus `TrustMarkEntry`, which requires `id`, whereas the trust marks themselves and the
resolve responses use `trust_mark_type` - publishing both names means that all of them understand the entry.

Note that the Nimbus OpenID Federation types (`EntityStatement`, `TrustMarkEntry`, ...) follow the drafts that
preceded OpenID Federation 1.0. The trust mark handling therefore works with `SignedJWT`:s and reads the claims
directly.

**4. Resolving OP:s**

An OP is configured by invoking the `federation_resolve_endpoint` of a configured trust anchor. The trust anchor
builds and validates the trust chain and applies the combined metadata policies, and returns the resolved metadata
in a signed resolve response. We validate that response - it must be signed by the trust anchor, be issued about the
entity we asked for, and not have expired - and use the metadata to configure the OP (endpoints and keys) so that it
can be used for authentication requests without any manual configuration. This is done automatically at start-up and
then at `refresh-interval` - no user interaction is involved, and the *OpenID Federation* view only reports the
status of the OP:s that have been discovered.

An OP that has once been configured is never removed. If a later refresh cannot resolve it, or if the federation
stops listing it, the configuration from the last successful resolution is kept and the OP is reported as
*Resolve failed* / *Not listed* along with the reason. A misbehaving OP, or trust anchor, therefore does not make an
OP disappear from the test client.

The resolution is deliberately delegated to the trust anchor rather than performed locally. A local resolver has to
walk the chain bottom-up using `authority_hints`, which fails as soon as an intermediate does not declare its
superiors - the trust anchor knows its own subordinates and can build the chain top-down.

### Configuration

```yaml
testclient:
  oidc:
    enabled: true
    # The immediate superiors of our RP:s - published as authority_hints.
    openid-fed-authorities:
      - https://intermediate.example.com
    federation:
      enabled: true
      trust-anchors:
        - entity-id: https://ta.example.com
          # Optional - received out-of-band. If not given, the trust anchor's self-declared keys are used (test only).
          jwks: classpath:trust-anchor.jwks
          # Optional - normally the resolve endpoint is read from the trust anchor's entity configuration. Assign it
          # if the trust anchor does not publish its entity configuration at its entity identifier, or advertises an
          # endpoint that can not be reached. Responses are always verified against the trust anchor keys.
          resolve-endpoint: https://ta.example.com/resolve
          # Whether OP:s should be discovered under this trust anchor (default true).
          discover-ops: true
          # Optional - the authorities whose subordinate listing endpoints are invoked when discovering OP:s. If not
          # given, the discovery starts at the trust anchor, i.e., the entire tree below it is traversed. The OP:s
          # that are found are always resolved against the trust anchor.
          subordinate-listing-sources:
            - entity-id: https://intermediate.example.com
              # Optional - normally the listing endpoint is read from the authority's entity configuration. Assign it
              # if the authority does not publish its entity configuration at its entity identifier, or advertises an
              # endpoint that can not be reached.
              list-endpoint: https://intermediate.example.com/subordinate_listing
      # Discover and configure OP:s automatically (default true).
      auto-configure-ops: true
      # How often the federation is traversed (default 10m).
      refresh-interval: 10m
      # The validity of the entity configurations we publish (default 24h).
      entity-configuration-validity: 24h
      # How many intermediate levels that are traversed when listing subordinates (default 5).
      max-listing-depth: 5
      # The client_registration_types published in our RP metadata (default automatic).
      client-registration-types:
        - automatic
      # The Swedish organization number (ten digits, no hyphen) published as organization_number in our RP metadata.
      # Required - an RP may override it in its own metadata.
      organization-number: "2021006883"
      # The logotype published as logo_uri in our RP metadata. Given as a path within this application, since the
      # logotype must be served from the same host as the RP entity identifiers (default /images/logo.svg).
      logo-path: /images/logo.svg
      # The subject_type published in our RP metadata (default pairwise).
      subject-type: pairwise
      # The trust marks published in the entity configurations of our RP:s. An RP may declare its own trust marks
      # (testclient.oidc.rps[].trust-marks), and in that case, these are not used for that RP.
      trust-marks:
          # The trust mark type, i.e., the identifier of the trust mark (named id in the drafts preceding 1.0).
        - trust-mark-type: https://tmi.example.com/trust-mark/test-sp
          # The trust mark issuer. The trust mark is fetched from its trust mark endpoint and must be signed by it.
          issuer: https://tmi.example.com
          # Optional - normally the trust mark endpoint is read from the issuer's entity configuration. Assign it if
          # the issuer does not publish its entity configuration at its entity identifier, or advertises an endpoint
          # that can not be reached.
          trust-mark-endpoint: https://tmi.example.com/trust_mark
          # Whether the trust mark is required. If a required trust mark can not be obtained, no entity
          # configuration is published for the RP (default false).
          required: false
          # Alternatively, a pre-issued trust mark received out-of-band. Nothing is then fetched from the issuer.
          #value: eyJhbGciOiJFUzI1NiIsInR5cCI6InRydXN0LW1hcmsrand0Iiwia2lkIjoi...
      # How long a fetched trust mark is used before it is fetched again (default 1h). A trust mark that expires
      # before this interval has passed is re-fetched when it expires.
      trust-mark-refresh-interval: 1h
      # The federation_entity metadata published in our entity configurations.
      entity-metadata:
        organization-name: "Sweden Connect"
        contacts:
          - operations@swedenconnect.se
        homepage-uri: https://www.swedenconnect.se
    rps:
      - path-suffix: testrp1
        description: "Test RP 1"
        metadata: ...
        # Optional - the trust marks of this RP. If given, the trust marks under
        # testclient.oidc.federation.trust-marks are not used for this RP.
        trust-marks:
          - trust-mark-type: https://tmi.example.com/trust-mark/test-sp
            issuer: https://tmi.example.com
```

### Endpoints

| Endpoint | Description |
| :--- | :--- |
| `GET /{rp-path-suffix}/.well-known/openid-federation` | The entity configuration for an RP. |
| `GET /oidc/federation/info` | Our federation entities (including their trust marks), the trust anchors and the status of the OP:s discovered from the federation. |
| `POST /oidc/federation/trust-marks/refresh` | Discards the cached trust marks and entity configurations - the trust marks are fetched from their issuers again. |
| `POST /oidc/federation/refresh` | Re-runs the discovery and resolution of the federation OP:s (this also happens automatically at `refresh-interval`). |
| `GET /oidc/federation/chain?entity_id=&trust_anchor=` | The trust chain of an entity, as reported by the trust anchor (serialized and decoded). |
| `GET /oidc/federation/entity-configuration?entity_id=` | The entity configuration of an entity (ours or a remote one). |

---

Copyright &copy; 2025, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
