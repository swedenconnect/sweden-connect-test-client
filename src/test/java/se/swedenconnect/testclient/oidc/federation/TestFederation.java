/*
 * Copyright 2025 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.testclient.oidc.federation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.api.ResolveClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.api.ResolveStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import net.minidev.json.JSONObject;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Helpers for building a small in-memory OpenID federation to test against.
 */
final class TestFederation {

  /** RP metadata used by the tests. */
  static final String RP_METADATA = """
      {
        "response_types" : [ "code" ],
        "grant_types" : [ "authorization_code" ],
        "client_name" : "Sweden Connect Test-RP",
        "token_endpoint_auth_method" : "private_key_jwt"
      }
      """;

  /** The JOSE object type of a trust mark. */
  static final JOSEObjectType TRUST_MARK_JWT_TYPE = new JOSEObjectType("trust-mark+jwt");

  private TestFederation() {
  }

  /**
   * Generates an RSA key.
   *
   * @return an {@link RSAKey} holding both the private and the public key
   */
  static RSAKey generateKey() {
    try {
      return new RSAKeyGenerator(2048)
          .keyID(UUID.randomUUID().toString())
          .generate();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to generate key", e);
    }
  }

  /**
   * Creates an {@link OidcRp} with a freshly generated credential.
   *
   * @param entityId the RP entity identifier
   * @return an {@link OidcRp}
   */
  static OidcRp createRp(final String entityId) {
    return createRp(entityId, RP_METADATA);
  }

  /**
   * Creates an {@link OidcRp} with a freshly generated credential and the supplied metadata.
   *
   * @param entityId the RP entity identifier
   * @param metadata the RP metadata (JSON)
   * @return an {@link OidcRp}
   */
  static OidcRp createRp(final String entityId, final String metadata) {
    try {
      final RSAKey key = generateKey();
      final PkiCredential credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
      final ClientCredentials credentials =
          new ClientCredentials(credential, null, credential, null, credential, credential, credential);
      return new OidcRp(entityId, "Test RP", "testrp1", credentials, metadata, entityId + "/redirect");
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to create test RP", e);
    }
  }

  /**
   * Creates a self-signed entity configuration.
   *
   * @param entityId the entity identifier
   * @param key the entity's key
   * @param metadataType the entity type of the metadata (may be {@code null})
   * @param metadata the metadata (may be {@code null})
   * @param federationEntityMetadata the {@code federation_entity} metadata (may be {@code null})
   * @param authorityHints the authority hints
   * @return a serialized entity statement
   */
  static String entityConfiguration(final String entityId, final RSAKey key, final EntityType metadataType,
      final JSONObject metadata, final FederationEntityMetadata federationEntityMetadata,
      final List<String> authorityHints) {

    final EntityID id = new EntityID(entityId);
    final EntityStatementClaimsSet claims = new EntityStatementClaimsSet(
        id, id, Date.from(Instant.now()), Date.from(Instant.now().plusSeconds(3600)),
        new JWKSet(key.toPublicJWK()));
    if (metadata != null) {
      claims.setMetadata(metadataType, metadata);
    }
    if (federationEntityMetadata != null) {
      claims.setFederationEntityMetadata(federationEntityMetadata);
    }
    if (!authorityHints.isEmpty()) {
      claims.setAuthorityHints(authorityHints.stream().map(EntityID::new).toList());
    }
    return sign(key, claims);
  }

  /**
   * Creates a self-signed entity configuration holding raw {@code federation_entity} metadata (used for endpoints
   * that the Nimbus {@link FederationEntityMetadata} does not cover, such as the trust mark endpoint).
   *
   * @param entityId the entity identifier
   * @param key the entity's key
   * @param federationEntityMetadata the {@code federation_entity} metadata as JSON
   * @return a serialized entity statement
   */
  static String entityConfiguration(final String entityId, final RSAKey key,
      final JSONObject federationEntityMetadata) {

    final EntityID id = new EntityID(entityId);
    final EntityStatementClaimsSet claims = new EntityStatementClaimsSet(
        id, id, Date.from(Instant.now()), Date.from(Instant.now().plusSeconds(3600)),
        new JWKSet(key.toPublicJWK()));
    claims.setMetadata(EntityType.FEDERATION_ENTITY, federationEntityMetadata);
    return sign(key, claims);
  }

  /**
   * Creates a trust mark.
   *
   * @param issuer the trust mark issuer
   * @param issuerKey the issuer's key
   * @param subject the entity that the trust mark is about
   * @param trustMarkType the trust mark type
   * @param expires when the trust mark expires (may be {@code null})
   * @param typeClaimName the claim to carry the trust mark type ({@code trust_mark_type} or {@code id})
   * @return a serialized trust mark
   */
  static String trustMark(final String issuer, final RSAKey issuerKey, final String subject,
      final String trustMarkType, final Instant expires, final String typeClaimName) {
    return trustMark(issuer, issuerKey, subject, trustMarkType, expires, typeClaimName, TRUST_MARK_JWT_TYPE);
  }

  /**
   * Creates a trust mark with the given JOSE object type.
   *
   * @param issuer the trust mark issuer
   * @param issuerKey the issuer's key
   * @param subject the entity that the trust mark is about
   * @param trustMarkType the trust mark type
   * @param expires when the trust mark expires (may be {@code null})
   * @param typeClaimName the claim to carry the trust mark type
   * @param joseType the JOSE object type ({@code typ}) of the JWT
   * @return a serialized trust mark
   */
  static String trustMark(final String issuer, final RSAKey issuerKey, final String subject,
      final String trustMarkType, final Instant expires, final String typeClaimName,
      final JOSEObjectType joseType) {

    try {
      final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
          .issuer(issuer)
          .subject(subject)
          .claim(typeClaimName, trustMarkType)
          .issueTime(Date.from(Instant.now()));
      if (expires != null) {
        claims.expirationTime(Date.from(expires));
      }
      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256)
              .type(joseType)
              .keyID(issuerKey.getKeyID())
              .build(),
          claims.build());
      jwt.sign(new RSASSASigner(issuerKey));
      return jwt.serialize();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to create trust mark", e);
    }
  }

  /**
   * Creates a subordinate statement.
   *
   * @param issuer the issuing authority
   * @param issuerKey the authority's key
   * @param subject the subject entity identifier
   * @param subjectKey the subject's key
   * @param metadataPolicy the metadata policy to include (may be {@code null})
   * @return a serialized entity statement
   */
  static String subordinateStatement(final String issuer, final RSAKey issuerKey, final String subject,
      final RSAKey subjectKey, final JSONObject metadataPolicy) {

    final EntityStatementClaimsSet claims = new EntityStatementClaimsSet(
        new EntityID(issuer), new EntityID(subject), Date.from(Instant.now()),
        Date.from(Instant.now().plusSeconds(3600)), new JWKSet(subjectKey.toPublicJWK()));
    if (metadataPolicy != null) {
      claims.setMetadataPolicyJSONObject(metadataPolicy);
    }
    return sign(issuerKey, claims);
  }

  /**
   * Creates a resolve response, i.e., what a trust anchor hands out from its resolve endpoint.
   *
   * @param trustAnchor the entity identifier of the trust anchor
   * @param trustAnchorKey the trust anchor's key
   * @param subject the resolved entity
   * @param metadataType the entity type of the resolved metadata
   * @param metadata the resolved metadata (policies already applied)
   * @param trustChain the serialized trust chain to include (may be {@code null})
   * @return a serialized resolve response
   */
  static String resolveResponse(final String trustAnchor, final RSAKey trustAnchorKey, final String subject,
      final EntityType metadataType, final JSONObject metadata, final List<String> trustChain) {

    try {
      final JSONObject metadataClaim = new JSONObject();
      metadataClaim.put(metadataType.getValue(), metadata);

      final ResolveClaimsSet claims = new ResolveClaimsSet(
          new EntityID(trustAnchor), new EntityID(subject), Date.from(Instant.now()),
          Date.from(Instant.now().plusSeconds(3600)), metadataClaim);
      if (trustChain != null) {
        claims.setTrustChain(TrustChain.parseSerialized(trustChain));
      }

      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256)
              .type(ResolveStatement.JOSE_OBJECT_TYPE)
              .keyID(trustAnchorKey.getKeyID())
              .build(),
          claims.toJWTClaimsSet());
      jwt.sign(new RSASSASigner(trustAnchorKey));
      return jwt.serialize();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to create resolve response", e);
    }
  }

  /**
   * Creates {@code federation_entity} metadata with fetch, list and resolve endpoints.
   *
   * @param baseUrl the base URL of the authority
   * @return a {@link FederationEntityMetadata}
   */
  static FederationEntityMetadata authorityMetadata(final String baseUrl) {
    final FederationEntityMetadata metadata = new FederationEntityMetadata(URI.create(baseUrl + "/fetch"));
    metadata.setFederationListEndpointURI(URI.create(baseUrl + "/list"));
    metadata.setFederationResolveEndpointURI(URI.create(baseUrl + "/resolve"));
    return metadata;
  }

  private static String sign(final RSAKey key, final EntityStatementClaimsSet claims) {
    try {
      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256)
              .type(EntityStatement.JOSE_OBJECT_TYPE)
              .keyID(key.getKeyID())
              .build(),
          claims.toJWTClaimsSet());
      jwt.sign(new RSASSASigner(key));
      return jwt.serialize();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to sign entity statement", e);
    }
  }

}
