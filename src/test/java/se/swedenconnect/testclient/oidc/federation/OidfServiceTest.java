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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.oidc.OidcOp;

import java.net.URI;
import java.util.List;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link OidfService} - subordinate listing and resolution via the trust anchor's resolve endpoint.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
class OidfServiceTest {

  private static final String TA = "https://ta.example.com";
  private static final String OP = "https://op.example.com";
  private static final String IM = "https://im.example.com";

  private static final MediaType ENTITY_STATEMENT = MediaType.parseMediaType("application/entity-statement+jwt");
  private static final MediaType RESOLVE_RESPONSE = MediaType.parseMediaType("application/resolve-response+jwt");

  private List<String> trustChain;
  private RSAKey taKey;
  private RSAKey opKey;
  private RSAKey imKey;
  private MockRestServiceServer server;
  private OidfProperties properties;
  private OidfService service;

  @BeforeEach
  void setup() {
    this.taKey = TestFederation.generateKey();
    this.opKey = TestFederation.generateKey();
    this.imKey = TestFederation.generateKey();

    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).ignoreExpectOrder(true).build();

    this.properties = new OidfProperties();
    this.properties.setEnabled(true);
    final OidfProperties.TrustAnchorProperties ta = new OidfProperties.TrustAnchorProperties();
    ta.setEntityId(TA);
    ta.setJwks(new JWKSet(this.taKey.toPublicJWK()));
    this.properties.getTrustAnchors().add(ta);

    // The OP entity configuration and the subordinate statement issued for it by the trust anchor.
    this.trustChain = List.of(
        TestFederation.entityConfiguration(
            OP, this.opKey, EntityType.OPENID_PROVIDER, this.opMetadata(), null, List.of(TA)),
        TestFederation.subordinateStatement(TA, this.taKey, OP, this.opKey, null));

    this.service = new OidfService(this.properties, new OidfClient(builder.build()));
  }

  @Test
  void resolvesOpUsingTheResolveEndpointOfTheTrustAnchor() {
    this.expectFederation();

    final OidcOp op = this.service.resolveOp(new EntityID(OP), new EntityID(TA));

    assertEquals(OP, op.getEntityId());
    assertEquals(OidcOp.Source.FEDERATION, op.getSource());
    assertEquals(TA, op.getTrustAnchor());
    assertEquals(OP + "/auth", op.getAuthorizationEndpoint());
    assertEquals(OP + "/token", op.getTokenEndpoint());
    assertEquals(OP + "/userinfo", op.getUserInfoEndpoint());
    assertEquals(OP + "/.well-known/openid-federation", op.getMetadataEndpoint());

    // The metadata is taken as-is from the resolve response - the trust anchor has already applied the policies.
    assertEquals("Test OP", op.getDisplayName());

    // The OP keys are picked up from the resolved metadata.
    assertNotNull(op.getJwks());
    assertEquals(this.opKey.getKeyID(), op.getJwks().getKeys().get(0).getKeyID());

    // The trust chain is the one reported by the trust anchor.
    assertEquals(2, op.getTrustChain().size());
    assertNotNull(op.getExpiresAt());
  }

  @Test
  void returnsTheTrustChainOfTheResolveResponse() {
    this.expectFederation();

    final List<String> chain = this.service.getTrustChain(new EntityID(OP), new EntityID(TA));

    assertEquals(this.trustChain, chain);
  }

  @Test
  void usesTheConfiguredResolveEndpointWhenAssigned() {
    // The trust anchor entity configuration is never fetched - the mock server fails on any unexpected request.
    this.properties.getTrustAnchors().get(0).setResolveEndpoint(URI.create(TA + "/other/resolve"));
    this.server.expect(ExpectedCount.once(), requestTo(startsWith(TA + "/other/resolve")))
        .andRespond(withSuccess(this.resolveResponse(), RESOLVE_RESPONSE));

    assertEquals(OP, this.service.resolveOp(new EntityID(OP), new EntityID(TA)).getEntityId());
  }

  @Test
  void discoversOpsUsingSubordinateListing() {
    this.expectFederation();
    this.server.expect(ExpectedCount.once(), requestTo(TA + "/list?entity_type=openid_provider"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));
    this.server.expect(ExpectedCount.once(), requestTo(TA + "/list"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));

    final OidfService.FederationRefreshResult result = this.service.refreshOps();

    assertTrue(result.errors().isEmpty(), () -> "Unexpected errors: " + result.errors());
    assertEquals(1, result.ops().size());
    assertEquals(OP, result.ops().get(0).getEntityId());
    assertEquals("Test OP", result.ops().get(0).getDisplayName());
  }

  @Test
  void discoversOpsFromConfiguredListingSourceUsingItsEntityConfiguration() {
    this.expectFederation();
    this.server.expect(ExpectedCount.manyTimes(), requestTo(IM + "/.well-known/openid-federation"))
        .andRespond(withSuccess(TestFederation.entityConfiguration(
                IM, this.imKey, null, null, TestFederation.authorityMetadata(IM), List.of(TA)),
            ENTITY_STATEMENT));
    this.server.expect(ExpectedCount.once(), requestTo(IM + "/list?entity_type=openid_provider"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));
    this.server.expect(ExpectedCount.once(), requestTo(IM + "/list"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));

    this.addListingSource(IM, null);

    final OidfService.FederationRefreshResult result = this.service.refreshOps();

    // No listing is made towards the trust anchor - the mock server fails on any unexpected request.
    assertTrue(result.errors().isEmpty(), () -> "Unexpected errors: " + result.errors());
    assertEquals(List.of(OP), result.ops().stream().map(OidcOp::getEntityId).toList());
    assertEquals(List.of(IM), this.service.getSubordinateListingSources());
  }

  @Test
  void discoversOpsFromConfiguredListingSourceUsingAnExplicitEndpoint() {
    this.expectFederation();
    // The intermediate does not publish its entity configuration at its entity identifier - the listing endpoint is
    // therefore assigned explicitly, and the entity configuration is never fetched.
    this.server.expect(ExpectedCount.once(), requestTo(IM + "/other/list?entity_type=openid_provider"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));
    this.server.expect(ExpectedCount.once(), requestTo(IM + "/other/list"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));

    this.addListingSource(IM, URI.create(IM + "/other/list"));

    final OidfService.FederationRefreshResult result = this.service.refreshOps();

    assertTrue(result.errors().isEmpty(), () -> "Unexpected errors: " + result.errors());
    assertEquals(List.of(OP), result.ops().stream().map(OidcOp::getEntityId).toList());
  }

  @Test
  void listsSubordinatesOfAuthority() {
    this.expectTrustAnchorConfiguration();
    this.server.expect(ExpectedCount.once(), requestTo(TA + "/list?entity_type=openid_provider"))
        .andRespond(withSuccess("[\"%s\"]".formatted(OP), MediaType.APPLICATION_JSON));

    final List<EntityID> subordinates =
        this.service.listSubordinates(new EntityID(TA), EntityType.OPENID_PROVIDER);

    assertEquals(List.of(new EntityID(OP)), subordinates);
  }

  @Test
  void failsWhenTheResolveResponseIsNotSignedByTheTrustAnchor() {
    this.expectTrustAnchorConfiguration();
    // Signed by the OP - not by the trust anchor whose keys we hold.
    this.server.expect(ExpectedCount.manyTimes(), requestTo(startsWith(TA + "/resolve")))
        .andRespond(withSuccess(TestFederation.resolveResponse(
            TA, this.opKey, OP, EntityType.OPENID_PROVIDER, this.opMetadata(), null), RESOLVE_RESPONSE));

    assertThrows(IllegalArgumentException.class,
        () -> this.service.resolveOp(new EntityID(OP), new EntityID(TA)));
  }

  @Test
  void failsWhenTheResolveResponseIsAboutAnotherEntity() {
    this.expectTrustAnchorConfiguration();
    this.server.expect(ExpectedCount.manyTimes(), requestTo(startsWith(TA + "/resolve")))
        .andRespond(withSuccess(TestFederation.resolveResponse(
            TA, this.taKey, IM, EntityType.OPENID_PROVIDER, this.opMetadata(), null), RESOLVE_RESPONSE));

    assertThrows(IllegalArgumentException.class,
        () -> this.service.resolveOp(new EntityID(OP), new EntityID(TA)));
  }

  @Test
  void failsWhenTheTrustAnchorDoesNotPublishAResolveEndpoint() {
    this.server.expect(ExpectedCount.manyTimes(), requestTo(TA + "/.well-known/openid-federation"))
        .andRespond(withSuccess(TestFederation.entityConfiguration(
            TA, this.taKey, null, null, null, List.of()), ENTITY_STATEMENT));

    assertThrows(IllegalArgumentException.class,
        () -> this.service.resolveOp(new EntityID(OP), new EntityID(TA)));
  }

  private void addListingSource(final String entityId, final URI listEndpoint) {
    final OidfProperties.ListingSourceProperties source = new OidfProperties.ListingSourceProperties();
    source.setEntityId(entityId);
    source.setListEndpoint(listEndpoint);
    this.properties.getTrustAnchors().get(0).getSubordinateListingSources().add(source);
  }

  private void expectFederation() {
    this.expectTrustAnchorConfiguration();
    this.server.expect(ExpectedCount.manyTimes(), requestTo(startsWith(TA + "/resolve")))
        .andRespond(withSuccess(this.resolveResponse(), RESOLVE_RESPONSE));
  }

  private void expectTrustAnchorConfiguration() {
    this.server.expect(ExpectedCount.manyTimes(), requestTo(TA + "/.well-known/openid-federation"))
        .andRespond(withSuccess(TestFederation.entityConfiguration(
                TA, this.taKey, null, null, TestFederation.authorityMetadata(TA), List.of()),
            ENTITY_STATEMENT));
  }

  private String resolveResponse() {
    return TestFederation.resolveResponse(
        TA, this.taKey, OP, EntityType.OPENID_PROVIDER, this.opMetadata(), this.trustChain);
  }

  private JSONObject opMetadata() {
    final JSONObject metadata = new JSONObject();
    metadata.put("issuer", OP);
    metadata.put("organization_name", "Test OP");
    metadata.put("authorization_endpoint", OP + "/auth");
    metadata.put("token_endpoint", OP + "/token");
    metadata.put("userinfo_endpoint", OP + "/userinfo");
    metadata.put("jwks", new JSONObject(new JWKSet(this.opKey.toPublicJWK()).toJSONObject()));
    return metadata;
  }

}
