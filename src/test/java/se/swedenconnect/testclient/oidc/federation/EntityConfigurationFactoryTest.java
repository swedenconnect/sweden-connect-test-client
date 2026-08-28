/*
 * Copyright 2025-2026 Sweden Connect
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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link EntityConfigurationFactory}.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
class EntityConfigurationFactoryTest {

  private static final String RP_ENTITY_ID = "https://client.example.com/testrp1";
  private static final String TRUST_ANCHOR = "https://ta.example.com";
  private static final String BASE_URL = "https://client.example.com";
  private static final String TRUST_MARK_ISSUER = "https://tmi.example.com";
  private static final String TRUST_MARK_TYPE = "https://tmi.example.com/trust-mark/test-sp";

  @Test
  void createsSelfSignedEntityConfiguration() throws Exception {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID);
    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties(), List.of(new EntityID(TRUST_ANCHOR)), BASE_URL, null);

    final EntityStatement statement = factory.createEntityConfiguration(rp);

    assertEquals(EntityStatement.JOSE_OBJECT_TYPE, statement.getSignedStatement().getHeader().getType());
    statement.verifySignatureOfSelfStatement();

    final EntityStatementClaimsSet claims = statement.getClaimsSet();
    assertTrue(claims.isSelfStatement());
    assertEquals(RP_ENTITY_ID, claims.getIssuerEntityID().getValue());
    assertEquals(RP_ENTITY_ID, claims.getSubjectEntityID().getValue());
    assertEquals(List.of(new EntityID(TRUST_ANCHOR)), claims.getAuthorityHints());

    // The published keys must not contain any private key material.
    assertNotNull(claims.getJWKSet());
    assertEquals(1, claims.getJWKSet().getKeys().size());
    assertFalse(claims.getJWKSet().getKeys().get(0).isPrivate());

    // The published key must be declared for signature use.
    final JWK publishedKey = claims.getJWKSet().getKeys().get(0);
    assertEquals(KeyUse.SIGNATURE, publishedKey.getKeyUse());
    assertEquals(statement.getSignedStatement().getHeader().getAlgorithm(), publishedKey.getAlgorithm());
    assertEquals(statement.getSignedStatement().getHeader().getKeyID(), publishedKey.getKeyID());
  }

  @Test
  @SuppressWarnings("unchecked")
  void publishesRpAndFederationEntityMetadata() throws Exception {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID);
    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties(), List.of(new EntityID(TRUST_ANCHOR)), BASE_URL, null);

    final EntityStatementClaimsSet claims = factory.createEntityConfiguration(rp).getClaimsSet();

    final JSONObject rpMetadata = claims.getMetadata(EntityType.OPENID_RELYING_PARTY);
    assertNotNull(rpMetadata);
    assertEquals("Sweden Connect Test-RP", rpMetadata.getAsString("client_name"));
    assertEquals(List.of("automatic"), rpMetadata.get("client_registration_types"));
    assertEquals(List.of(rp.getMetadata().getRedirectionURI().toASCIIString()), rpMetadata.get("redirect_uris"));

    // Fields that are mandatory in the Sweden Connect federation.
    assertEquals("pairwise", rpMetadata.getAsString("subject_type"));
    assertEquals("2021006883", rpMetadata.getAsString("organization_number"));
    assertEquals(BASE_URL + "/images/logo.svg", rpMetadata.getAsString("logo_uri"));

    // The client keys published in the metadata must be declared for signature use.
    final JWKSet metadataKeys = JWKSet.parse((Map<String, Object>) rpMetadata.get("jwks"));
    assertEquals(1, metadataKeys.getKeys().size());
    assertEquals(KeyUse.SIGNATURE, metadataKeys.getKeys().get(0).getKeyUse());
    assertFalse(metadataKeys.getKeys().get(0).isPrivate());

    assertNotNull(claims.getFederationEntityMetadata());
    assertEquals("Sweden Connect", claims.getFederationEntityMetadata().getOrganizationName());
    assertEquals(List.of("operations@swedenconnect.se"), claims.getFederationEntityMetadata().getContacts());
  }

  @Test
  void rpDeclaredMetadataOverridesTheDefaults() throws Exception {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID, """
        {
          "response_types" : [ "code" ],
          "client_name" : "Sweden Connect Test-RP",
          "subject_type" : "public",
          "organization_number" : "5566778899",
          "logo_uri" : "https://client.example.com/images/other-logo.svg",
          "token_endpoint_auth_method" : "private_key_jwt"
        }
        """);
    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties(), List.of(new EntityID(TRUST_ANCHOR)), BASE_URL, null);

    final JSONObject rpMetadata = factory.createEntityConfiguration(rp).getClaimsSet()
        .getMetadata(EntityType.OPENID_RELYING_PARTY);

    assertNotNull(rpMetadata);
    assertEquals("public", rpMetadata.getAsString("subject_type"));
    assertEquals("5566778899", rpMetadata.getAsString("organization_number"));
    assertEquals("https://client.example.com/images/other-logo.svg", rpMetadata.getAsString("logo_uri"));
  }

  @Test
  void publishesTrustMarks() {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID);
    final RSAKey issuerKey = TestFederation.generateKey();
    final String trustMark = TestFederation.trustMark(TRUST_MARK_ISSUER, issuerKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
        Instant.now().plusSeconds(3600), "trust_mark_type");

    final OidfProperties properties = properties();
    final OidfProperties.TrustMarkProperties tm = new OidfProperties.TrustMarkProperties();
    tm.setTrustMarkType(TRUST_MARK_TYPE);
    tm.setIssuer(TRUST_MARK_ISSUER);
    tm.setValue(trustMark);
    properties.getTrustMarks().add(tm);

    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties, List.of(new EntityID(TRUST_ANCHOR)), BASE_URL,
        new TrustMarkResolver(properties, new OidfClient(RestClient.builder().build()), Map.of()));

    final EntityStatementClaimsSet claims = factory.createEntityConfiguration(rp).getClaimsSet();

    final Object entries = claims.toJSONObject().get("trust_marks");
    assertInstanceOf(List.class, entries);
    assertEquals(1, ((List<?>) entries).size());
    final Map<?, ?> entry = (Map<?, ?>) ((List<?>) entries).get(0);
    assertEquals(trustMark, entry.get("trust_mark"));

    // The trust mark type is published both as trust_mark_type (OpenID Federation 1.0) and as id (the drafts that
    // preceded it), so that consumers of either version understand the entry.
    assertEquals(TRUST_MARK_TYPE, entry.get("trust_mark_type"));
    assertEquals(TRUST_MARK_TYPE, entry.get("id"));
  }

  @Test
  void doesNotPublishAnEntityConfigurationWithoutARequiredTrustMark() {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID);

    final OidfProperties properties = properties();
    final OidfProperties.TrustMarkProperties tm = new OidfProperties.TrustMarkProperties();
    tm.setTrustMarkType(TRUST_MARK_TYPE);
    tm.setIssuer(TRUST_MARK_ISSUER);
    tm.setValue("this-is-not-a-jwt");
    tm.setRequired(true);
    properties.getTrustMarks().add(tm);

    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties, List.of(new EntityID(TRUST_ANCHOR)), BASE_URL,
        new TrustMarkResolver(properties, new OidfClient(RestClient.builder().build()), Map.of()));

    final IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> factory.createEntityConfiguration(rp));
    assertTrue(e.getMessage().contains(TRUST_MARK_TYPE), e.getMessage());
  }

  @Test
  void cachesEntityConfiguration() {
    final OidcRp rp = TestFederation.createRp(RP_ENTITY_ID);
    final EntityConfigurationFactory factory = new EntityConfigurationFactory(
        properties(), List.of(new EntityID(TRUST_ANCHOR)), BASE_URL, null);

    assertSame(factory.getEntityConfiguration(rp), factory.getEntityConfiguration(rp));
  }

  private static OidfProperties properties() {
    final OidfProperties properties = new OidfProperties();
    properties.setEnabled(true);
    properties.getEntityMetadata().setOrganizationName("Sweden Connect");
    properties.getEntityMetadata().setContacts(List.of("operations@swedenconnect.se"));
    properties.setOrganizationNumber("2021006883");
    properties.setSubjectType("pairwise");
    return properties;
  }

}
