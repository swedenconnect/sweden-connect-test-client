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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.thymeleaf.standard.serializer.StandardJavaScriptSerializer;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.NATURAL_PERSON_INFO;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.NATURAL_PERSON_NUMBER;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.PERSONAL_IDENTITY_NUMBER;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.TOKEN_ENDPOINT;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.USERINFO_ENDPOINT;

/**
 * Tests for how the UserInfo endpoint is called - automatically when the OP redirects back ({@link OidcController}),
 * and manually from the authentication result ({@link OidcRestController}).
 *
 * @author Martin Lindström
 */
class OidcUserInfoFlowTest {

  private static final String WWW_AUTHENTICATE = "Bearer error=\"invalid_token\"";
  private static final String USERINFO = "{\"sub\":\"user\",\"given_name\":\"Frida\"}";
  private static final String USERINFO_WITH_TIMES = """
      { "sub": "user", "updated_at": 0, "iat": 1789650256.0, "exp": "1789650256", "address": { "exp": 1789650256 } }""";

  private MockHttpSession session;
  private MockRestServiceServer server;
  private OidcController controller;
  private OidcRestController restController;
  private OidcRp rp;

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    final RestClient client = builder.build();
    this.controller = new OidcController(this.session, client);
    this.restController = new OidcRestController(List.of(), Mockito.mock(OidcOpRegistry.class), this.session,
        Mockito.mock(OIDCOPMetadataFetcher.class), null, null, client);
    this.rp = UserInfoTestSupport.rp();
    UserInfoTestSupport.authenticationInSession(this.session, this.rp);
  }

  // Automatic call

  @Test
  void userInfoIsCalledWhenTheSettingIsChecked() throws Exception {
    this.session.setAttribute(OidcController.SESSION_NAME_CALL_USERINFO, true);
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(method(HttpMethod.GET))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + ACCESS_TOKEN))
        .andRespond(withSuccess(USERINFO, MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertNull(response.getOpError());
    assertEquals(UserInfoResult.Status.RECEIVED, response.getUserInfoResult().getStatus());
    assertFalse(response.getUserInfoResult().isManual());
    assertEquals(Map.of("sub", "user", "given_name", "Frida"), response.getUserInfoClaims());
    assertEquals("JSON", response.getUserInfoProtection().getFormat());
    // birthdate was requested from UserInfo, but not received
    assertEquals(Set.of("birthdate"), response.getMissingUserInfoClaims().keySet());

    final ScopeValidationResult personInfo = scope(response.getScopeValidation(), NATURAL_PERSON_INFO);
    assertEquals(ScopeValidationResult.Status.OK, personInfo.getStatus());
    assertTrue(personInfo.getClaims().stream().noneMatch(ScopeValidationResult.ClaimValidationResult::isNotChecked));
    assertEquals(ScopeValidationResult.Status.OK, scope(response.getScopeValidation(), NATURAL_PERSON_NUMBER).getStatus());
  }

  @Test
  void userInfoIsCalledWhenTheSettingIsMissing() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withSuccess(USERINFO, MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertEquals(UserInfoResult.Status.RECEIVED, response.getUserInfoResult().getStatus());
  }

  @Test
  void userInfoIsNotCalledWhenTheSettingIsUnchecked() throws Exception {
    this.session.setAttribute(OidcController.SESSION_NAME_CALL_USERINFO, false);
    // Only the token request is expected - a UserInfo request would fail the test
    this.expectTokenRequest();

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertNull(response.getOpError());
    assertNull(response.getErrors());
    assertEquals(ACCESS_TOKEN, response.getAccessToken());
    assertEquals("196911292032", response.getIdTokenClaims().get(PERSONAL_IDENTITY_NUMBER));
    assertEquals(UserInfoResult.Status.NOT_CALLED, response.getUserInfoResult().getStatus());
    assertNull(response.getUserInfoClaims());
    assertNull(response.getUserInfoProtection());
    assertNull(response.getMissingUserInfoClaims());

    final ScopeValidationResult personInfo = scope(response.getScopeValidation(), NATURAL_PERSON_INFO);
    assertEquals(ScopeValidationResult.Status.NOT_CHECKED, personInfo.getStatus());
    assertTrue(personInfo.getMessage().contains("UserInfo was not called"), personInfo.getMessage());
    personInfo.getClaims().forEach(c -> assertEquals("UserInfo was not called", c.getNotCheckedReason()));
    // The claims of the ID token are reported as before
    final ScopeValidationResult personNumber = scope(response.getScopeValidation(), NATURAL_PERSON_NUMBER);
    assertEquals(ScopeValidationResult.Status.OK, personNumber.getStatus());
    assertEquals("ID Token", personNumber.getClaims().get(0).getReceivedIn());
  }

  @Test
  void aFailedAutomaticCallKeepsTheTokenResults() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
            .header(HttpHeaders.WWW_AUTHENTICATE, WWW_AUTHENTICATE)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"error\":\"invalid_token\"}"));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertNull(response.getOpError());
    assertNull(response.getErrors());
    assertEquals(ACCESS_TOKEN, response.getAccessToken());
    assertEquals(ACCESS_TOKEN, response.getResponse().get("access_token"));
    assertEquals("196911292032", response.getIdTokenClaims().get(PERSONAL_IDENTITY_NUMBER));

    final UserInfoResult result = response.getUserInfoResult();
    assertEquals(UserInfoResult.Status.FAILED, result.getStatus());
    assertFalse(result.isManual());
    assertEquals(401, result.getHttpStatus());
    assertEquals(WWW_AUTHENTICATE, result.getWwwAuthenticate());
    assertEquals("{\"error\":\"invalid_token\"}", result.getBody());
    assertNull(response.getUserInfoClaims());
    assertNull(response.getMissingUserInfoClaims());

    final ScopeValidationResult personInfo = scope(response.getScopeValidation(), NATURAL_PERSON_INFO);
    assertEquals(ScopeValidationResult.Status.NOT_CHECKED, personInfo.getStatus());
    personInfo.getClaims().forEach(c -> assertEquals("the UserInfo call failed", c.getNotCheckedReason()));
  }

  @Test
  void aNetworkErrorInTheAutomaticCallKeepsTheTokenResults() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withException(new IOException("Connection reset")));

    final OIDCResponse response = this.redirect();

    assertNull(response.getOpError());
    assertEquals(ACCESS_TOKEN, response.getAccessToken());
    assertEquals(UserInfoResult.Status.FAILED, response.getUserInfoResult().getStatus());
    assertNull(response.getUserInfoResult().getHttpStatus());
    assertTrue(response.getUserInfoResult().getError().contains("Connection reset"));
  }

  @Test
  void anUnreadableSuccessResponseIsHandledAsBefore() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withSuccess("garbage", MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    assertEquals(UserInfoResult.Status.RECEIVED, response.getUserInfoResult().getStatus());
    assertEquals(Map.of(), response.getUserInfoClaims());
    assertTrue(response.getUserInfoProtection().getNote().startsWith("Failed to parse UserInfo response"));
    assertEquals(Set.of("birthdate"), response.getMissingUserInfoClaims().keySet());
  }

  @Test
  void aFailedTokenRequestIsStillAnOpError() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withStatus(HttpStatus.BAD_REQUEST).contentType(MediaType.APPLICATION_JSON)
            .body("{\"error\":\"invalid_grant\",\"error_description\":\"Bad code\"}"));

    final String view = this.controller.handleRedirection(new MockHttpServletRequest(), "rp", null, null, "state",
        UserInfoTestSupport.OP, "code").getViewName();

    this.server.verify();
    assertEquals("redirect:/oidc/redirect/rp?error=invalid_grant&error_description=Bad code", view);
  }

  @Test
  void theUserInfoResultReachesThePage() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, WWW_AUTHENTICATE));
    final OIDCResponse response = this.redirect();

    // The result is handed to the page by Thymeleaf's inline JavaScript serialization (sc-client.html)
    final StringWriter written = new StringWriter();
    new StandardJavaScriptSerializer(true).serializeValue(response, written);
    final JsonNode page = JsonMapper.builder().build().readTree(written.toString());

    assertEquals("FAILED", page.get("userInfoResult").get("status").asString());
    assertEquals(401, page.get("userInfoResult").get("http_status").asInt());
    assertEquals(WWW_AUTHENTICATE, page.get("userInfoResult").get("www_authenticate").asString());
    final JsonNode claim = page.get("scopeValidation").get(1).get("claims").get(0);
    assertEquals("the UserInfo call failed", claim.get("notCheckedReason").asString());
    assertFalse(claim.has("notChecked"));
  }

  // Times of the time claims

  @Test
  void theTimeClaimsOfTheTokensAndUserInfoAreGivenTimes() throws Exception {
    this.expectTokenRequest(tokenResponseWithTimes());
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withSuccess(USERINFO_WITH_TIMES, MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertEquals(Map.of("iat", "2026-09-17 13:04:16 UTC", "exp", "2026-09-17 14:04:16 UTC",
        "auth_time", "2026-09-17 13:03:16 UTC"), response.getIdTokenClaimTimes());
    assertEquals(Map.of("exp", "2026-09-17 13:09:16 UTC"), response.getAccessTokenClaimTimes());
    assertEquals(Map.of("updated_at", "1970-01-01 00:00:00 UTC"), response.getUserInfoClaimTimes());

    // The claims stay as received
    assertEquals(1789650256L, response.getIdTokenClaims().get("iat"));
    assertEquals("1789650256", response.getIdTokenClaims().get("updated_at"));
    assertEquals(3600, response.getResponse().get("expires_in"));
    assertEquals(0, response.getUserInfoClaims().get("updated_at"));
    assertEquals(1789650256.0, response.getUserInfoClaims().get("iat"));
    assertEquals(Map.of("exp", 1789650256), response.getUserInfoClaims().get("address"));
  }

  @Test
  void theTimesReachThePage() throws Exception {
    this.expectTokenRequest(tokenResponseWithTimes());
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withSuccess(USERINFO_WITH_TIMES, MediaType.APPLICATION_JSON));
    final OIDCResponse response = this.redirect();

    final StringWriter written = new StringWriter();
    new StandardJavaScriptSerializer(true).serializeValue(response, written);
    final JsonNode page = JsonMapper.builder().build().readTree(written.toString());

    assertEquals("2026-09-17 13:04:16 UTC", page.get("idTokenClaimTimes").get("iat").asString());
    assertEquals("2026-09-17 13:09:16 UTC", page.get("accessTokenClaimTimes").get("exp").asString());
    assertEquals("1970-01-01 00:00:00 UTC", page.get("userInfoClaimTimes").get("updated_at").asString());
    assertEquals(1789650256L, page.get("idTokenClaims").get("iat").asLong());
  }

  @Test
  void anOpaqueAccessTokenAndAFailedUserInfoCallGiveNoTimes() throws Exception {
    this.expectTokenRequest();
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withStatus(HttpStatus.UNAUTHORIZED));

    final OIDCResponse response = this.redirect();

    assertEquals(Map.of(), response.getAccessTokenClaimTimes());
    assertEquals(Map.of(), response.getIdTokenClaimTimes());
    assertNull(response.getUserInfoClaimTimes());
  }

  @Test
  void aManualCallGivesTheTimesOfTheUserInfoClaims() {
    this.session.setAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS, UserInfoTestSupport.idTokenClaims());
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withSuccess(USERINFO_WITH_TIMES, MediaType.APPLICATION_JSON));

    final JsonNode json = JsonMapper.builder().build().valueToTree(
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel(ACCESS_TOKEN, "GET")));

    final JsonNode evaluation = json.get("evaluation");
    assertEquals(1, evaluation.get("userInfoClaimTimes").size());
    assertEquals("1970-01-01 00:00:00 UTC", evaluation.get("userInfoClaimTimes").get("updated_at").asString());
    // The claims of the JSON viewer stay as received
    assertEquals(0, json.get("exchange").get("claims").get("updated_at").asInt());
  }

  // Manual call

  @Test
  void aManualCallWorksAfterTheResponseHasLeftTheSession() throws Exception {
    this.session.setAttribute(OidcController.SESSION_NAME_CALL_USERINFO, false);
    this.expectTokenRequest();
    this.redirect();
    // MainController removes the response once the result page has been rendered
    this.session.removeAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);
    this.server.verify();
    this.server.reset();

    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(method(HttpMethod.GET))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer another-token"))
        .andRespond(withSuccess(USERINFO, MediaType.APPLICATION_JSON));

    final OidcRestController.UserInfoCallModel result =
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel("another-token", null));

    this.server.verify();
    final UserInfoExchange exchange = result.getExchange();
    assertEquals(200, exchange.getStatus());
    assertEquals("GET", exchange.getRequest().method());
    assertEquals(USERINFO_ENDPOINT, exchange.getRequest().url());
    assertEquals("Bearer another-token", exchange.getRequest().headers().get(HttpHeaders.AUTHORIZATION));
    assertEquals(USERINFO, exchange.getBody());

    final UserInfoEvaluation evaluation = result.getEvaluation();
    assertEquals(UserInfoResult.Status.RECEIVED, evaluation.getUserInfoResult().getStatus());
    assertTrue(evaluation.getUserInfoResult().isManual());
    assertEquals(Map.of("sub", "user", "given_name", "Frida"), evaluation.getUserInfoClaims());
    assertEquals(Set.of("birthdate"), evaluation.getMissingUserInfoClaims().keySet());
    assertEquals(ScopeValidationResult.Status.OK, scope(evaluation.getScopeValidation(), NATURAL_PERSON_INFO).getStatus());
    // The ID token claims of the authentication are still used
    assertEquals(ScopeValidationResult.Status.OK,
        scope(evaluation.getScopeValidation(), NATURAL_PERSON_NUMBER).getStatus());
  }

  @Test
  void aFailedManualCallClearsTheUserInfoClaims() throws Exception {
    this.session.setAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS, UserInfoTestSupport.idTokenClaims());
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
        .andExpect(content().string(""))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, WWW_AUTHENTICATE));

    final OidcRestController.UserInfoCallModel result =
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel("", "POST"));

    this.server.verify();
    assertEquals(401, result.getExchange().getStatus());
    assertEquals(List.of(WWW_AUTHENTICATE), result.getExchange().getResponseHeaders().get(HttpHeaders.WWW_AUTHENTICATE));
    assertNull(result.getExchange().getRequest().headers().get(HttpHeaders.AUTHORIZATION));

    final UserInfoEvaluation evaluation = result.getEvaluation();
    assertEquals(UserInfoResult.Status.FAILED, evaluation.getUserInfoResult().getStatus());
    assertTrue(evaluation.getUserInfoResult().isManual());
    assertEquals(401, evaluation.getUserInfoResult().getHttpStatus());
    assertNull(evaluation.getUserInfoClaims());
    assertNull(evaluation.getUserInfoProtection());
    assertNull(evaluation.getMissingUserInfoClaims());
    final ScopeValidationResult personInfo = scope(evaluation.getScopeValidation(), NATURAL_PERSON_INFO);
    assertEquals(ScopeValidationResult.Status.NOT_CHECKED, personInfo.getStatus());
    personInfo.getClaims().forEach(c -> assertEquals("the UserInfo call failed", c.getNotCheckedReason()));
  }

  @Test
  void aManualNetworkErrorIsReportedAsAFailedCall() {
    this.session.setAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS, UserInfoTestSupport.idTokenClaims());
    this.server.expect(requestTo(USERINFO_ENDPOINT)).andRespond(withException(new IOException("Connection refused")));

    final OidcRestController.UserInfoCallModel result =
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel(ACCESS_TOKEN, "GET"));

    assertNull(result.getExchange().getStatus());
    assertNotNull(result.getExchange().getError());
    assertEquals(UserInfoResult.Status.FAILED, result.getEvaluation().getUserInfoResult().getStatus());
  }

  @Test
  void aManualCallWithoutAuthenticationInTheSessionSendsNothing() {
    this.session.clearAttributes();

    final OidcRestController.UserInfoCallModel result =
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel(ACCESS_TOKEN, "GET"));

    this.server.verify();
    assertNotNull(result.getExchange().getError());
    assertNull(result.getExchange().getRequest());
    assertNull(result.getEvaluation());
  }

  @Test
  void aManualCallWithoutAnAuthenticationResultIsOnlyReported() {
    this.server.expect(ExpectedCount.once(), requestTo(USERINFO_ENDPOINT))
        .andRespond(withSuccess(USERINFO, MediaType.APPLICATION_JSON));

    final OidcRestController.UserInfoCallModel result =
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel(ACCESS_TOKEN, "GET"));

    this.server.verify();
    assertEquals(200, result.getExchange().getStatus());
    assertNull(result.getEvaluation());
  }

  @Test
  void theManualCallIsSerializedForTheBrowser() {
    this.session.setAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS, UserInfoTestSupport.idTokenClaims());
    this.server.expect(requestTo(USERINFO_ENDPOINT))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, WWW_AUTHENTICATE));

    final JsonNode json = JsonMapper.builder().build().valueToTree(
        this.restController.sendUserInfoRequest(new OidcRestController.UserInfoRequestModel(ACCESS_TOKEN, "GET")));

    final JsonNode exchange = json.get("exchange");
    assertEquals("GET", exchange.get("request").get("method").asString());
    assertEquals("Bearer " + ACCESS_TOKEN, exchange.get("request").get("headers").get("Authorization").asString());
    assertEquals(401, exchange.get("status").asInt());
    assertEquals(WWW_AUTHENTICATE, exchange.get("response_headers").get("WWW-Authenticate").get(0).asString());
    assertFalse(exchange.has("successful"));
    assertEquals("FAILED", json.get("evaluation").get("userInfoResult").get("status").asString());
    assertTrue(json.get("evaluation").get("userInfoResult").get("manual").asBoolean());
  }

  private void expectTokenRequest() {
    this.expectTokenRequest(UserInfoTestSupport.tokenResponse());
  }

  private void expectTokenRequest(final String tokenResponse) {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withSuccess(tokenResponse, MediaType.APPLICATION_JSON));
  }

  /**
   * A token response with an ID token and a signed access token holding time claims - valid ones, and an
   * {@code updated_at} that is a string.
   */
  private static String tokenResponseWithTimes() throws Exception {
    final String idToken = new PlainJWT(new JWTClaimsSet.Builder()
        .issuer(UserInfoTestSupport.OP)
        .subject("user")
        .audience(UserInfoTestSupport.RP)
        .issueTime(new Date(1789650256000L))
        .expirationTime(new Date(1789653856000L))
        .claim("auth_time", 1789650196L)
        .claim("updated_at", "1789650256")
        .claim(PERSONAL_IDENTITY_NUMBER, "196911292032")
        .build()).serialize();
    final SignedJWT accessToken = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder()
        .subject("user")
        .expirationTime(new Date(1789650556000L))
        .claim("iat", -1)
        .build());
    accessToken.sign(new ECDSASigner(new ECKeyGenerator(Curve.P_256).generate()));
    return """
        { "access_token": "%s", "token_type": "Bearer", "expires_in": 3600, "id_token": "%s" }"""
        .formatted(accessToken.serialize(), idToken);
  }

  private OIDCResponse redirect() throws Exception {
    final String view = this.controller.handleRedirection(new MockHttpServletRequest(), "rp", null, null, "state",
        UserInfoTestSupport.OP, "code").getViewName();
    assertEquals("redirect:/", view);
    return (OIDCResponse) this.session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);
  }

  private static ScopeValidationResult scope(final List<ScopeValidationResult> results, final String scope) {
    return results.stream().filter(r -> scope.equals(r.getScope())).findFirst().orElseThrow();
  }
}
