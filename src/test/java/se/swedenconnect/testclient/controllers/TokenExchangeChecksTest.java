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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.ACCESS_TOKEN_TYPE;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.GRANT_TYPE;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.FAIL;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.INFO;
import static se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome.PASS;

/**
 * Tests for {@link TokenExchangeChecks}.
 *
 * @author Simon Tardell
 */
class TokenExchangeChecksTest {

  private static final String API2 = "https://api2.example.com";

  @Test
  void aKeycloakStyleExchangeFailsOnActAndAChangedSub() {
    final List<TokenExchangeChecks.Check> checks = TokenExchangeChecks.evaluate(request(),
        Map.of("sub", "user-1", "auth_time", 100, "scope", "openid api1"),
        Map.of("access_token", "x", "issued_token_type", ACCESS_TOKEN_TYPE, "token_type", "Bearer",
            "refresh_token", "r"),
        Map.of("sub", "user-2", "aud", List.of(API2, "other"), "auth_time", 100, "azp", "rs1", "scope", "api2"));

    assertEquals(FAIL, outcome(checks, "No refresh token"));
    assertEquals(FAIL, outcome(checks, "The response includes scope"));
    assertEquals(PASS, outcome(checks, "aud corresponds"));
    assertEquals(FAIL, outcome(checks, "sub is the sub"));
    assertEquals(PASS, outcome(checks, "auth_time of the subject token"));
    assertEquals(FAIL, outcome(checks, "act identifies"));
    assertEquals(INFO, outcome(checks, "client_id is"));
    assertEquals(INFO, outcome(checks, "Scopes of the issued token"));
    assertEquals("api2 - where the user is the resource owner, the AS may only grant scopes the user originally"
        + " authorized", detail(checks, "Scopes of the issued token"));
  }

  @Test
  void actSubMustBeTheRequestingClient() {
    final List<TokenExchangeChecks.Check> checks = TokenExchangeChecks.evaluate(request(), Map.of("sub", "u"),
        Map.of("access_token", "x"), Map.of("sub", "u", "client_id", "rs1", "act", Map.of("sub", "app")));

    assertEquals(PASS, outcome(checks, "act identifies"));
    assertEquals(FAIL, outcome(checks, "act.sub is"));
  }

  @Test
  void withoutAResponseOnlyTheRequestIsChecked() {
    final MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
    request.add("grant_type", GRANT_TYPE);
    request.add("subject_token_type", ACCESS_TOKEN_TYPE);
    request.add("scope", "api2");

    final List<TokenExchangeChecks.Check> checks = TokenExchangeChecks.evaluate(request, null, null, null);

    assertEquals(4, checks.size());
    assertEquals(INFO, outcome(checks, "A target indicator"));
    assertEquals(FAIL, outcome(checks, "requested_token_type"));
  }

  private static MultiValueMap<String, String> request() {
    final MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
    request.add("grant_type", GRANT_TYPE);
    request.add("subject_token_type", ACCESS_TOKEN_TYPE);
    request.add("requested_token_type", ACCESS_TOKEN_TYPE);
    request.add("resource", API2);
    request.add("client_id", "rs1");
    return request;
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
