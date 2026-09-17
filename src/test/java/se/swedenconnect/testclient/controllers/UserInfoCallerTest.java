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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.ACCESS_TOKEN;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.USERINFO_ENDPOINT;

/**
 * Tests for {@link UserInfoCaller}.
 *
 * @author Martin Lindström
 */
class UserInfoCallerTest {

  private static final String ACCEPT = "application/json, application/jwt";

  private MockRestServiceServer server;
  private UserInfoCaller caller;
  private OidcRp rp;

  @BeforeEach
  void setUp() {
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    this.caller = new UserInfoCaller(builder.build());
    this.rp = UserInfoTestSupport.rp();
  }

  @Test
  void getSendsTheAccessTokenAsBearerInTheAuthorizationHeader() {
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(method(HttpMethod.GET))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + ACCESS_TOKEN))
        .andExpect(header(HttpHeaders.ACCEPT, ACCEPT))
        .andRespond(withSuccess("{\"sub\":\"user\",\"birthdate\":\"1969-11-29\"}", MediaType.APPLICATION_JSON));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.GET, this.rp);

    this.server.verify();
    assertTrue(exchange.isSuccessful());
    assertEquals(200, exchange.getStatus());
    assertEquals("GET", exchange.getRequest().method());
    assertEquals(USERINFO_ENDPOINT, exchange.getRequest().url());
    assertEquals(Map.of(HttpHeaders.ACCEPT, ACCEPT, HttpHeaders.AUTHORIZATION, "Bearer " + ACCESS_TOKEN),
        exchange.getRequest().headers());
    assertEquals(Map.of("sub", "user", "birthdate", "1969-11-29"), exchange.getClaims());
    assertEquals("JSON", exchange.getProtection().getFormat());
    assertEquals("{\"sub\":\"user\",\"birthdate\":\"1969-11-29\"}", exchange.getBody());
    assertNull(exchange.getError());
  }

  @Test
  void postHasAnEmptyBodyAndTheAccessTokenInTheAuthorizationHeader() {
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + ACCESS_TOKEN))
        .andExpect(content().string(""))
        .andRespond(withSuccess("{\"sub\":\"user\"}", MediaType.APPLICATION_JSON));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.POST, this.rp);

    this.server.verify();
    assertTrue(exchange.isSuccessful());
    assertEquals("POST", exchange.getRequest().method());
    assertEquals(Map.of("sub", "user"), exchange.getClaims());
  }

  @Test
  void anEmptyAccessTokenIsNotSent() {
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED));
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED));

    final UserInfoExchange empty = this.caller.call(USERINFO_ENDPOINT, "", HttpMethod.GET, this.rp);
    final UserInfoExchange missing = this.caller.call(USERINFO_ENDPOINT, null, HttpMethod.POST, this.rp);

    this.server.verify();
    assertEquals(Map.of(HttpHeaders.ACCEPT, ACCEPT), empty.getRequest().headers());
    assertEquals(Map.of(HttpHeaders.ACCEPT, ACCEPT), missing.getRequest().headers());
  }

  @Test
  void anErrorStatusIsReportedWithItsHeadersAndBody() {
    final String wwwAuthenticate = "Bearer error=\"invalid_token\", error_description=\"The token has expired\"";
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
            .header(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"error\":\"invalid_token\"}"));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, "expired", HttpMethod.GET, this.rp);

    assertFalse(exchange.isSuccessful());
    assertEquals(401, exchange.getStatus());
    assertEquals(wwwAuthenticate, exchange.getResponseHeader("www-authenticate"));
    assertEquals("{\"error\":\"invalid_token\"}", exchange.getBody());
    assertNull(exchange.getClaims());
    assertNull(exchange.getProtection());
    assertNull(exchange.getError());

    final UserInfoResult result = UserInfoResult.failed(exchange, true);
    assertEquals(UserInfoResult.Status.FAILED, result.getStatus());
    assertTrue(result.isManual());
    assertEquals(401, result.getHttpStatus());
    assertEquals(wwwAuthenticate, result.getWwwAuthenticate());
    assertEquals("{\"error\":\"invalid_token\"}", result.getBody());
  }

  @Test
  void aServerErrorIsReported() {
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.GET, this.rp);

    assertFalse(exchange.isSuccessful());
    assertEquals(500, exchange.getStatus());
    final UserInfoResult result = UserInfoResult.failed(exchange, false);
    assertNull(result.getBody());
    assertNull(result.getWwwAuthenticate());
  }

  @Test
  void aNetworkErrorIsReported() {
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withException(new IOException("Connection refused")));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.GET, this.rp);

    assertFalse(exchange.isSuccessful());
    assertNull(exchange.getStatus());
    assertNotNull(exchange.getError());
    assertTrue(exchange.getError().contains("Connection refused"), exchange.getError());
    assertNotNull(exchange.getRequest());
  }

  @Test
  void aSuccessResponseThatCannotBeReadIsReportedAsSuccessful() {
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withSuccess("this is not JSON", MediaType.APPLICATION_JSON));

    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.GET, this.rp);

    assertTrue(exchange.isSuccessful());
    assertEquals(Map.of(), exchange.getClaims());
    assertTrue(exchange.getProtection().getNote().startsWith("Failed to parse UserInfo response"),
        exchange.getProtection().getNote());
  }

  @Test
  void anOpWithoutUserInfoEndpointIsReported() {
    final UserInfoExchange exchange = this.caller.call(null, ACCESS_TOKEN, HttpMethod.GET, this.rp);

    assertFalse(exchange.isSuccessful());
    assertEquals("The OP has no UserInfo endpoint", exchange.getError());
  }

  @Test
  void onlyGetAndPostAreSent() {
    final UserInfoExchange exchange = this.caller.call(USERINFO_ENDPOINT, ACCESS_TOKEN, HttpMethod.PUT, this.rp);

    this.server.verify();
    assertFalse(exchange.isSuccessful());
    assertNotNull(exchange.getError());
  }
}
