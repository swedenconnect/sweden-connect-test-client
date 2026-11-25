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
package se.swedenconnect.testclient.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static se.swedenconnect.testclient.controllers.ClientAuthenticationChecks.JWT_BEARER;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.FAIL;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.INFO;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.PASS;

/**
 * Tests for {@link ClientAuthenticationChecks}.
 *
 * @author Simon Tardell
 */
class ClientAuthenticationChecksTest {

  private static final String TOKEN_ENDPOINT = "https://as.example.se/token";
  private static final String CLIENT = "https://rp.example.se";
  private static final String GOOD_JTI = "q8J2xZ7vN1cR5tY0uW3eA6sD9fG4hK2lP7mB1nV8";

  @Test
  void aCompliantAssertionPasses() {
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), params(), assertion("RS256",
        claims(TOKEN_ENDPOINT, GOOD_JTI)), Set.of());

    checks.stream().filter(c -> !"MAY".equals(c.level()))
        .forEach(c -> assertEquals(PASS, c.outcome(), c.requirement() + ": " + c.detail()));
    assertEquals(INFO, outcome(checks, "Additional claims"));
    assertEquals("None", detail(checks, "Additional claims"));
    assertTrue(checks.stream().allMatch(c -> ClientAuthenticationChecks.SECTION.equals(c.section())));
  }

  @Test
  void theIssuerAsAudienceAndAUuidJtiFail() {
    // The test client's defaults: aud is the OP's issuer, and jti a random UUID
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), params(), assertion("RS256",
        claims("https://as.example.se", "4953bf5c-cddb-43c9-b7c4-f979f165fbe7")), Set.of());

    assertEquals(FAIL, outcome(checks, "aud is the URL of the token endpoint"));
    assertEquals(FAIL, outcome(checks, "jti is included"));
    assertTrue(detail(checks, "jti is included").contains("122 random bits"));
  }

  @Test
  void anAudienceArrayWithOnlyTheTokenEndpointPasses() {
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), params(), assertion("ES256",
        claims(List.of(TOKEN_ENDPOINT), GOOD_JTI)), Set.of());
    assertEquals(PASS, outcome(checks, "aud is the URL of the token endpoint"));

    final List<TokenExchangeChecks.Check> two = evaluate(Map.of(), params(), assertion("ES256",
        claims(List.of(TOKEN_ENDPOINT, "https://as.example.se"), GOOD_JTI)), Set.of());
    assertEquals(FAIL, outcome(two, "aud is the URL of the token endpoint"));
  }

  @Test
  void aReusedJtiFails() {
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), params(), assertion("RS256",
        claims(TOKEN_ENDPOINT, GOOD_JTI)), Set.of(GOOD_JTI));
    assertEquals(FAIL, outcome(checks, "A new assertion is used"));
  }

  @Test
  void secretBasedAuthenticationFails() {
    final Map<String, String> post = new LinkedHashMap<>();
    post.put("grant_type", "authorization_code");
    post.put("client_id", CLIENT);
    post.put("client_secret", "s");
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), post, null, Set.of());
    assertEquals(FAIL, outcome(checks, "The client authenticates with private_key_jwt only"));
    assertEquals(FAIL, outcome(checks, "client_assertion_type is"));
    assertEquals(FAIL, outcome(checks, "client_assertion is included"));
    assertEquals(3, checks.size());

    final List<TokenExchangeChecks.Check> basic = evaluate(Map.of("Authorization", "Basic eDp5"),
        Map.of("grant_type", "authorization_code"), null, Set.of());
    assertTrue(detail(basic, "The client authenticates with private_key_jwt only").contains("client_secret_basic"));

    final List<TokenExchangeChecks.Check> hs = evaluate(Map.of(), params(), assertion("HS256",
        claims(TOKEN_ENDPOINT, GOOD_JTI)), Set.of());
    assertEquals(FAIL, outcome(hs, "The client authenticates with private_key_jwt only"));
    assertEquals(FAIL, outcome(hs, "The assertion is signed with the client's private key"));
  }

  @Test
  void missingClaimsFail() {
    final Map<String, Object> claims = new LinkedHashMap<>(claims(TOKEN_ENDPOINT, GOOD_JTI));
    claims.remove("iat");
    claims.remove("exp");
    claims.remove("jti");
    claims.put("sub", "someone-else");
    claims.put("extra", "x");
    final List<TokenExchangeChecks.Check> checks = evaluate(Map.of(), params(), assertion("RS256", claims),
        Set.of());

    assertEquals(PASS, outcome(checks, "iss is the client ID"));
    assertEquals(FAIL, outcome(checks, "sub is the client ID"));
    assertEquals(FAIL, outcome(checks, "iat"));
    assertEquals(FAIL, outcome(checks, "exp"));
    assertEquals(FAIL, outcome(checks, "jti is included"));
    assertEquals("extra", detail(checks, "Additional claims"));
  }

  @Test
  void entropyEstimates() {
    assertEquals(122, ClientAuthenticationChecks.estimateEntropy("4953bf5c-cddb-43c9-b7c4-f979f165fbe7").bits());
    assertEquals(0, ClientAuthenticationChecks.estimateEntropy("4953bf5c-cddb-13c9-b7c4-f979f165fbe7").bits());
    // 32 hex characters = 128 bits, 22 Base64url characters = 132 bits, the profile's 16-character example = 95 bits
    assertEquals(128, ClientAuthenticationChecks.estimateEntropy("0123456789abcdef0123456789abcdef").bits(), 0.001);
    assertTrue(ClientAuthenticationChecks.estimateEntropy("AB786tg9kLTMNB90AB786_").bits() >= 128);
    assertTrue(ClientAuthenticationChecks.estimateEntropy("AB786tg9kLTMNB90").bits() < 128);
  }

  @Test
  void jtisAreRememberedInTheSession() {
    final MockHttpSession session = new MockHttpSession();
    assertTrue(ClientAuthenticationChecks.earlierJtis(session).isEmpty());
    ClientAuthenticationChecks.rememberJti(session, assertion("RS256", claims(TOKEN_ENDPOINT, GOOD_JTI)));
    ClientAuthenticationChecks.rememberJti(session, null);
    assertEquals(Set.of(GOOD_JTI), ClientAuthenticationChecks.earlierJtis(session));
  }

  private static List<TokenExchangeChecks.Check> evaluate(final Map<String, String> headers,
      final Map<String, String> parameters, final SentTokenRequest.ClientAssertion assertion, final Set<String> jtis) {
    return ClientAuthenticationChecks.evaluate(TOKEN_ENDPOINT, headers, parameters, assertion, CLIENT, jtis);
  }

  private static Map<String, String> params() {
    final Map<String, String> p = new LinkedHashMap<>();
    p.put("grant_type", "authorization_code");
    p.put("client_assertion_type", JWT_BEARER);
    p.put("client_assertion", "a.b.c");
    return p;
  }

  private static Map<String, Object> claims(final Object aud, final String jti) {
    final Map<String, Object> c = new LinkedHashMap<>();
    c.put("iss", CLIENT);
    c.put("sub", CLIENT);
    c.put("aud", aud);
    c.put("iat", 1683200128L);
    c.put("exp", 1683200188L);
    c.put("jti", jti);
    return c;
  }

  private static SentTokenRequest.ClientAssertion assertion(final String alg, final Map<String, Object> claims) {
    return new SentTokenRequest.ClientAssertion(Map.of("alg", alg), claims, null);
  }

  private static TokenExchangeChecks.Outcome outcome(final List<TokenExchangeChecks.Check> checks,
      final String requirement) {
    return find(checks, requirement).outcome();
  }

  private static String detail(final List<TokenExchangeChecks.Check> checks, final String requirement) {
    return find(checks, requirement).detail();
  }

  private static TokenExchangeChecks.Check find(final List<TokenExchangeChecks.Check> checks,
      final String requirement) {
    return checks.stream().filter(c -> c.requirement().startsWith(requirement)).findFirst()
        .orElseThrow(() -> new AssertionError("No check '" + requirement + "' in " + checks));
  }
}
