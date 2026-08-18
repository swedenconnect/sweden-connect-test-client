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
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.oidc.federation.TrustMarkResolver.ResolvedTrustMark;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link TrustMarkResolver} - fetching and validating the trust marks that our RP:s publish.
 */
class TrustMarkResolverTest {

  private static final String RP_ENTITY_ID = "https://client.example.com/testrp1";
  private static final String TMI = "https://tmi.example.com";
  private static final String TRUST_MARK_TYPE = "https://tmi.example.com/trust-mark/test-sp";

  private static final MediaType TRUST_MARK = MediaType.parseMediaType("application/trust-mark+jwt");
  private static final MediaType ENTITY_STATEMENT = MediaType.parseMediaType("application/entity-statement+jwt");

  private static final String TRUST_MARK_URL = UriComponentsBuilder.fromUriString(TMI + "/trust_mark")
      .queryParam("sub", RP_ENTITY_ID)
      .queryParam("trust_mark_type", TRUST_MARK_TYPE)
      .build()
      .encode()
      .toUriString();

  private RSAKey tmiKey;
  private MockRestServiceServer server;
  private OidcRp rp;
  private OidfProperties properties;
  private OidfClient client;

  @BeforeEach
  void setup() {
    this.tmiKey = TestFederation.generateKey();
    this.rp = TestFederation.createRp(RP_ENTITY_ID);

    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).ignoreExpectOrder(true).build();
    this.client = new OidfClient(builder.build());

    this.properties = new OidfProperties();
    this.properties.setEnabled(true);
  }

  @Test
  void fetchesTrustMarkFromTheIssuer() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "trust_mark_type"),
        TRUST_MARK);

    final List<ResolvedTrustMark> trustMarks = this.resolver().resolve(this.rp);

    assertEquals(1, trustMarks.size());
    final ResolvedTrustMark trustMark = trustMarks.get(0);
    assertNull(trustMark.error());
    assertNotNull(trustMark.trustMark());
    assertEquals(TRUST_MARK_TYPE, trustMark.trustMarkType());
    assertEquals(TMI, trustMark.issuer());
    assertTrue(trustMark.isValidAt(Instant.now()));

    // Both the OpenID Federation 1.0 name and the one used by the earlier drafts are published.
    final JSONObject entry = trustMark.toJSONObject();
    assertEquals(TRUST_MARK_TYPE, entry.getAsString("trust_mark_type"));
    assertEquals(TRUST_MARK_TYPE, entry.getAsString("id"));
    assertEquals(trustMark.trustMark().serialize(), entry.getAsString("trust_mark"));

    this.server.verify();
  }

  @Test
  void acceptsTheLegacyIdClaim() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "id"),
        TRUST_MARK);

    final ResolvedTrustMark resolved = this.resolver().resolve(this.rp).get(0);

    assertNull(resolved.error());
    assertNotNull(resolved.trustMark());
    assertEquals(TRUST_MARK_TYPE, resolved.trustMarkType());
  }

  @Test
  void rejectsAJwtThatIsNotATrustMark() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "trust_mark_type", new JOSEObjectType("JWT")),
        TRUST_MARK);

    final ResolvedTrustMark resolved = this.resolver().resolve(this.rp).get(0);

    assertNull(resolved.trustMark());
    assertNotNull(resolved.error());
    assertTrue(resolved.error().contains("is of type JWT"), resolved.error());
  }

  @Test
  void cachesTheTrustMark() {
    // The issuer is contacted once - the second round is served from the cache.
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "trust_mark_type"),
        TRUST_MARK);

    final TrustMarkResolver resolver = this.resolver();
    assertNotNull(resolver.resolve(this.rp).get(0).trustMark());
    assertNotNull(resolver.resolve(this.rp).get(0).trustMark());

    this.server.verify();
  }

  @Test
  void reportsTrustMarkIssuedAboutAnotherEntity() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, "https://other.example.com", TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "trust_mark_type"),
        TRUST_MARK);

    final ResolvedTrustMark resolved = this.resolver().resolve(this.rp).get(0);

    assertNull(resolved.trustMark());
    assertNotNull(resolved.error());
    assertTrue(resolved.error().contains("issued about https://other.example.com"), resolved.error());
  }

  @Test
  void reportsTrustMarkSignedByAnotherKey() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, TestFederation.generateKey(), RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().plusSeconds(3600), "trust_mark_type"),
        TRUST_MARK);

    final ResolvedTrustMark resolved = this.resolver().resolve(this.rp).get(0);

    assertNull(resolved.trustMark());
    assertNotNull(resolved.error());
    assertTrue(resolved.error().contains("Signature validation"), resolved.error());
  }

  @Test
  void reportsExpiredTrustMark() {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
            Instant.now().minusSeconds(10), "trust_mark_type"),
        TRUST_MARK);

    final ResolvedTrustMark resolved = this.resolver().resolve(this.rp).get(0);

    assertNull(resolved.trustMark());
    assertNotNull(resolved.error());
    assertTrue(resolved.error().contains("expired"), resolved.error());
  }

  @Test
  void usesAConfiguredTrustMarkWithoutContactingTheIssuer() {
    final String trustMark = TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
        Instant.now().plusSeconds(3600), "trust_mark_type");
    final OidfProperties.TrustMarkProperties tm = trustMarkProperties();
    tm.setValue(trustMark);
    this.properties.getTrustMarks().add(tm);

    final ResolvedTrustMark resolved =
        new TrustMarkResolver(this.properties, this.client, Map.of()).resolve(this.rp).get(0);

    assertNull(resolved.error());
    assertNotNull(resolved.trustMark());
    assertEquals(trustMark, resolved.trustMark().serialize());

    this.server.verify();
  }

  @Test
  void anRpDeclaringItsOwnTrustMarksDoesNotGetTheGlobalOnes() {
    final OidfProperties.TrustMarkProperties global = trustMarkProperties();
    global.setTrustMarkType("https://tmi.example.com/trust-mark/other");
    this.properties.getTrustMarks().add(global);

    final OidfProperties.TrustMarkProperties own = trustMarkProperties();
    own.setValue(TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE,
        Instant.now().plusSeconds(3600), "trust_mark_type"));

    final TrustMarkResolver resolver =
        new TrustMarkResolver(this.properties, this.client, Map.of(this.rp.getPathSuffix(), List.of(own)));

    final List<ResolvedTrustMark> trustMarks = resolver.resolve(this.rp);
    assertEquals(1, trustMarks.size());
    assertEquals(TRUST_MARK_TYPE, trustMarks.get(0).trustMarkType());
    assertNotNull(trustMarks.get(0).trustMark());
  }

  private TrustMarkResolver resolver() {
    this.properties.getTrustMarks().add(trustMarkProperties());
    return new TrustMarkResolver(this.properties, this.client, Map.of());
  }

  private static OidfProperties.TrustMarkProperties trustMarkProperties() {
    final OidfProperties.TrustMarkProperties tm = new OidfProperties.TrustMarkProperties();
    tm.setTrustMarkType(TRUST_MARK_TYPE);
    tm.setIssuer(TMI);
    return tm;
  }

  private void expectIssuerConfiguration(final ExpectedCount count) {
    final JSONObject metadata = new JSONObject();
    metadata.put("federation_trust_mark_endpoint", TMI + "/trust_mark");
    this.server.expect(count, requestTo(TMI + "/.well-known/openid-federation"))
        .andRespond(withSuccess(TestFederation.entityConfiguration(TMI, this.tmiKey, metadata), ENTITY_STATEMENT));
  }

  private void expectTrustMark(final ExpectedCount count, final String body, final MediaType mediaType) {
    this.server.expect(count, requestTo(TRUST_MARK_URL)).andRespond(withSuccess(body, mediaType));
  }

}
