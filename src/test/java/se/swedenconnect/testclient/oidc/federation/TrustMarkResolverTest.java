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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link TrustMarkResolver} - fetching and validating the trust marks that our RP:s publish.
 *
 * @author Martin Lindström
 * @author Felix Hellman
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

  @Test
  void noTrustMarksAreFetchedForAnRpWithoutEntityConfiguration() {
    final OidcRp rpWithoutEc = TestFederation.createRp(RP_ENTITY_ID, TestFederation.RP_METADATA, false);
    this.properties.getTrustMarks().add(trustMarkProperties());
    final TrustMarkResolver resolver = new TrustMarkResolver(this.properties, this.client,
        Map.of(rpWithoutEc.getPathSuffix(), List.of(trustMarkProperties())));

    assertTrue(resolver.resolve(rpWithoutEc).isEmpty());
    assertTrue(resolver.refresh(rpWithoutEc).isEmpty());

    // No expectations were set up - any request to the issuer would fail the verification.
    this.server.verify();
  }

  @Test
  void theDefaultRetryIntervalIsOneMinute() {
    assertEquals(Duration.ofMinutes(1), new OidfProperties().getTrustMarkRetryInterval());
  }

  @Test
  void aFailedFetchIsRetriedAfterTheRetryInterval() {
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    // The issuer is down - the failure is reported, and no new attempt is made within the retry interval.
    this.expectIssuerDown();
    assertNotNull(resolver.resolve(this.rp).get(0).error());
    clock.advance(Duration.ofSeconds(59));
    assertNull(resolver.resolve(this.rp).get(0).trustMark());
    this.server.verify();

    // The issuer is up again - the trust mark is fetched once the retry interval has passed.
    this.server.reset();
    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(2)));
    clock.advance(Duration.ofSeconds(1));
    final ResolvedTrustMark resolved = resolver.resolve(this.rp).get(0);
    assertNull(resolved.error());
    assertNotNull(resolved.trustMark());
    this.server.verify();
  }

  @Test
  void theRetryIntervalIsConfigurable() {
    this.properties.setTrustMarkRetryInterval(Duration.ofMinutes(5));
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    this.expectIssuerDown();
    assertNull(resolver.resolve(this.rp).get(0).trustMark());
    clock.advance(Duration.ofMinutes(4));
    assertNull(resolver.resolve(this.rp).get(0).trustMark());
    this.server.verify();

    this.server.reset();
    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(2)));
    clock.advance(Duration.ofMinutes(1));
    assertNotNull(resolver.resolve(this.rp).get(0).trustMark());
    this.server.verify();
  }

  @Test
  void aFailedRenewalKeepsTheCurrentTrustMarkAndIsRetried() {
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(3)));
    final ResolvedTrustMark first = resolver.resolve(this.rp).get(0);
    assertNotNull(first.trustMark());
    this.server.verify();

    // The regular renewal (after the refresh interval) fails - the current trust mark is kept.
    this.server.reset();
    this.expectIssuerDown();
    clock.advance(this.properties.getTrustMarkRefreshInterval());
    assertSame(first, resolver.resolve(this.rp).get(0));
    clock.advance(Duration.ofSeconds(59));
    assertSame(first, resolver.resolve(this.rp).get(0));
    this.server.verify();

    // The retry succeeds - the trust mark is replaced.
    this.server.reset();
    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(4)));
    clock.advance(Duration.ofSeconds(1));
    final ResolvedTrustMark renewed = resolver.resolve(this.rp).get(0);
    assertNotNull(renewed.trustMark());
    assertNotEquals(first.trustMark().serialize(), renewed.trustMark().serialize());
    this.server.verify();
  }

  @Test
  void aKeptTrustMarkIsDroppedWhenItExpires() {
    this.properties.setTrustMarkRefreshInterval(Duration.ofSeconds(60));
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    final Instant expiresAt = clock.instant().plusSeconds(90);
    this.expectIssuerUp(expiresAt);
    final ResolvedTrustMark first = resolver.resolve(this.rp).get(0);
    assertNotNull(first.trustMark());
    this.server.verify();

    // The renewal fails - the trust mark is kept, and the next attempt is made when it expires (before the retry
    // interval has passed).
    this.server.reset();
    this.expectIssuerDown();
    clock.advance(Duration.ofSeconds(60));
    assertSame(first, resolver.resolve(this.rp).get(0));
    this.server.verify();

    this.server.reset();
    this.expectIssuerDown();
    clock.advance(Duration.ofSeconds(30));
    final ResolvedTrustMark expired = resolver.resolve(this.rp).get(0);
    assertNull(expired.trustMark());
    assertNotNull(expired.error());
    assertFalse(expired.isValidAt(clock.instant()));
    this.server.verify();
  }

  @Test
  void refreshFetchesTheTrustMarkAgain() {
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(2)));
    final ResolvedTrustMark first = resolver.resolve(this.rp).get(0);
    this.server.verify();

    // Not due - but refresh fetches it anyway.
    this.server.reset();
    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(3)));
    final ResolvedTrustMark refreshed = resolver.refresh(this.rp).get(0);
    assertNotNull(refreshed.trustMark());
    assertNotEquals(first.trustMark().serialize(), refreshed.trustMark().serialize());
    this.server.verify();

    // A refresh with the issuer down keeps the current trust mark.
    this.server.reset();
    this.expectIssuerDown();
    assertSame(refreshed, resolver.refresh(this.rp).get(0));
    this.server.verify();
  }

  @Test
  void refreshRetriesAFailedFetchAtOnce() {
    final TestFederation.TestClock clock = new TestFederation.TestClock();
    final TrustMarkResolver resolver = this.resolver(clock);

    this.expectIssuerDown();
    assertNull(resolver.resolve(this.rp).get(0).trustMark());
    this.server.verify();

    this.server.reset();
    this.expectIssuerUp(Instant.now().plus(Duration.ofHours(2)));
    assertNotNull(resolver.refresh(this.rp).get(0).trustMark());
    this.server.verify();
  }

  private TrustMarkResolver resolver(final TestFederation.TestClock clock) {
    this.properties.getTrustMarks().add(trustMarkProperties());
    return new TrustMarkResolver(this.properties, this.client, Map.of(), clock);
  }

  private void expectIssuerDown() {
    this.server.expect(ExpectedCount.once(), requestTo(TMI + "/.well-known/openid-federation"))
        .andRespond(withServerError());
  }

  private void expectIssuerUp(final Instant expiresAt) {
    this.expectIssuerConfiguration(ExpectedCount.once());
    this.expectTrustMark(ExpectedCount.once(),
        TestFederation.trustMark(TMI, this.tmiKey, RP_ENTITY_ID, TRUST_MARK_TYPE, expiresAt, "trust_mark_type"),
        TRUST_MARK);
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
