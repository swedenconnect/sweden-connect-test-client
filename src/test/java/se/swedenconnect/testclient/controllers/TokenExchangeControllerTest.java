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

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import se.swedenconnect.testclient.config.OidcProperties;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.ExpectedCount.never;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.anything;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.OP;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.RP;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.TOKEN_ENDPOINT;

/**
 * Tests for {@link TokenExchangeController}.
 *
 * @author Simon Tardell
 */
class TokenExchangeControllerTest {

  private static final String API1 = "https://api1.example.com";
  private static final String API2 = "https://api2.example.com";
  private static final String RESOURCE_URL = API1 + "/api/hello";

  private MockHttpSession session;
  private MockRestServiceServer server;
  private TokenExchangeController controller;
  private OidcRp rp;
  private OidcProperties properties;
  private OIDCOPMetadataFetcher fetcher;
  private final List<String> sentBodies = new ArrayList<>();

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    this.properties = new OidcProperties();
    // Both checks are off by default - the tests below look at them
    this.properties.getChecks().setEnaChaining(true);
    this.properties.getChecks().setSdgClientAuthentication(true);
    final OidcProperties properties = this.properties;
    final OidcProperties.ProtectedResource resource = new OidcProperties.ProtectedResource();
    resource.setName("API 1");
    resource.setUrl(RESOURCE_URL);
    resource.setResource(API1);
    properties.getProtectedResources().add(resource);
    this.fetcher = new OIDCOPMetadataFetcher(builder.build()) {
      @Override
      public JSONObject getOPMetadata(final OidcOp oidcOp) {
        final JSONObject metadata = new JSONObject();
        metadata.put("scopes_supported", List.of("openid", "api1", "api2"));
        return metadata;
      }
    };
    this.controller = new TokenExchangeController(this.session, builder.build(), properties, this.fetcher);
    this.rp = UserInfoTestSupport.rp();
    UserInfoTestSupport.authenticationInSession(this.session, this.rp);
  }

  @Test
  void theRequestIsSentWithTheRpAsClientAndEveryTargetAsAParameterOfItsOwn() throws Exception {
    final String subjectToken = token(Map.of("sub", "user-1", "aud", API1, "acr", "loa3", "scope", "openid api1"));
    final String issued = token(Map.of("sub", "user-1", "aud", API2, "acr", "loa3", "scope", "api2",
        "client_id", RP, "act", Map.of("sub", RP)));
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
        .andExpect(this::recordBody)
        .andRespond(withSuccess(tokenResponse(issued), MediaType.APPLICATION_JSON));

    final TokenExchangeController.TokenExchangeResult result =
        this.controller.sendTokenExchangeRequest(request(subjectToken, List.of(API2, API2 + "/other"), "api2"));

    this.server.verify();
    final Map<String, List<String>> sent = URLUtils.parseParameters(this.sentBodies.getFirst());
    assertEquals(List.of(TokenExchangeChecks.GRANT_TYPE), sent.get("grant_type"));
    assertEquals(List.of(subjectToken), sent.get("subject_token"));
    assertEquals(List.of(TokenExchangeChecks.ACCESS_TOKEN_TYPE), sent.get("subject_token_type"));
    assertEquals(List.of(TokenExchangeChecks.ACCESS_TOKEN_TYPE), sent.get("requested_token_type"));
    assertEquals(List.of(API2, API2 + "/other"), sent.get("resource"));
    assertEquals(List.of("api2"), sent.get("scope"));
    assertEquals(List.of(RP), sent.get("client_id"));
    assertFalse(sent.containsKey("audience"));
    assertFalse(sent.containsKey("actor_token"));
    assertFalse(sent.containsKey("actor_token_type"));
    assertFalse(sent.containsKey("code"));
    assertFalse(sent.containsKey("redirect_uri"));

    final JWSObject assertion = JWSObject.parse(sent.get("client_assertion").getFirst());
    assertTrue(assertion.verify(new RSASSAVerifier(
        (RSAPublicKey) this.rp.getCredentials().getCredentialForSigning().getPublicKey())));
    assertEquals(RP, assertion.getPayload().toJSONObject().get("sub"));
    assertEquals(OP, assertion.getPayload().toJSONObject().get("aud"));

    assertNull(result.getError());
    assertEquals(sent, result.getRequest().parameters());
    assertEquals("user-1", result.getSubjectToken().claims().get("sub"));
    assertEquals(API2, result.getIssuedToken().claims().get("aud"));
    assertNotNull(result.getChecks());
    // The token in this test meets every requirement except that aud is missing the second resource
    final List<TokenExchangeChecks.Check> failed = result.getChecks().stream()
        .filter(c -> c.outcome() == TokenExchangeChecks.Outcome.FAIL).toList();
    assertEquals(1, failed.size(), failed.toString());
    assertTrue(failed.getFirst().requirement().startsWith("aud"));
  }

  @Test
  void theDefaultsSuggestTheProtectedResourcesAndTheScopesOfTheOp() {
    final TokenExchangeController.TokenExchangeDefaults defaults = this.controller.tokenExchangeDefaults();

    assertEquals(TOKEN_ENDPOINT, defaults.tokenEndpoint());
    assertEquals(RP, defaults.clientId());
    assertEquals(List.of(API1), defaults.resources());
    assertEquals(List.of("openid", "api1", "api2"), defaults.scopes());

    this.session.clearAttributes();
    final TokenExchangeController.TokenExchangeDefaults none = this.controller.tokenExchangeDefaults();
    assertNull(none.tokenEndpoint());
    assertEquals(List.of(API1), none.resources());
    assertEquals(List.of(), none.scopes());
  }

  @Test
  void clientSecretBasicIsSentInTheAuthorizationHeader() {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(header(HttpHeaders.AUTHORIZATION, TokenRequestFactory.basicAuthorization(RP, "secret")))
        .andExpect(this::recordBody)
        .andRespond(withSuccess(tokenResponse("opaque"), MediaType.APPLICATION_JSON));
    final TokenExchangeController.TokenExchangeRequestModel model = request("opaque-subject", List.of(), null);
    model.setAudience(List.of(API2));
    model.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_BASIC);
    model.setClientSecret("secret");

    final TokenExchangeController.TokenExchangeResult result = this.controller.sendTokenExchangeRequest(model);

    this.server.verify();
    final Map<String, List<String>> sent = URLUtils.parseParameters(this.sentBodies.getFirst());
    assertEquals(List.of(API2), sent.get("audience"));
    assertFalse(sent.containsKey("client_id"));
    assertFalse(sent.containsKey("client_assertion"));
    assertNull(result.getSubjectToken());
    assertNull(result.getIssuedToken());
    assertEquals("opaque", result.getResponse().get("access_token"));
  }

  @Test
  void anErrorResponseIsReportedWithTheRequestChecks() {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withStatus(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"error\":\"invalid_target\",\"error_description\":\"bad resource\"}"));

    final TokenExchangeController.TokenExchangeResult result =
        this.controller.sendTokenExchangeRequest(request("subject", List.of(), null));

    assertEquals("invalid_target", result.getError().getError());
    assertEquals(400, result.getError().getHttpStatus());
    assertNull(result.getResponse());
    assertTrue(result.getChecks().stream().anyMatch(c -> c.outcome() == TokenExchangeChecks.Outcome.FAIL
        && c.requirement().contains("target indicator")));
  }

  @Test
  void withTheChecksOffTheResultHasNoChecks() {
    this.properties.getChecks().setEnaChaining(false);
    this.properties.getChecks().setSdgClientAuthentication(false);
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    this.controller = new TokenExchangeController(this.session, builder.build(), this.properties, this.fetcher);
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withSuccess(tokenResponse("opaque"), MediaType.APPLICATION_JSON));

    final TokenExchangeController.TokenExchangeResult result =
        this.controller.sendTokenExchangeRequest(request("subject", List.of(API2), null));

    this.server.verify();
    assertEquals("opaque", result.getResponse().get("access_token"));
    assertNull(result.getChecks());
    assertNull(result.getClientAuthChecks());
  }

  @Test
  void withoutAnAuthenticationNothingIsSent() {
    this.session.clearAttributes();
    this.server.expect(never(), anything());

    final TokenExchangeController.TokenExchangeResult result =
        this.controller.sendTokenExchangeRequest(request("subject", List.of(API2), null));

    this.server.verify();
    assertTrue(result.getError().getMessage().contains("no OIDC authentication"));
    assertNull(result.getRequest());
  }

  @Test
  void onlyConfiguredProtectedResourcesAreCalled() {
    this.server.expect(requestTo(RESOURCE_URL))
        .andExpect(method(HttpMethod.GET))
        .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer at"))
        .andRespond(withSuccess("{\"ok\":true}", MediaType.APPLICATION_JSON));

    assertEquals(List.of(new TokenExchangeController.ProtectedResourceInfo(0, "API 1", RESOURCE_URL)),
        this.controller.protectedResources());
    final TokenExchangeController.ResourceCall call =
        this.controller.callProtectedResource(new TokenExchangeController.ResourceCallModel(0, " at "));
    assertEquals(200, call.getStatus());
    assertEquals(Map.of("ok", true), call.getJson());

    final TokenExchangeController.ResourceCall unknown =
        this.controller.callProtectedResource(new TokenExchangeController.ResourceCallModel(1, "at"));
    assertEquals("Unknown protected resource", unknown.getError());
    this.server.verify();
  }

  private static TokenExchangeController.TokenExchangeRequestModel request(final String subjectToken,
      final List<String> resource, final String scope) {
    final TokenExchangeController.TokenExchangeRequestModel model =
        new TokenExchangeController.TokenExchangeRequestModel();
    model.setSubjectToken(subjectToken);
    model.setSubjectTokenType(TokenExchangeChecks.ACCESS_TOKEN_TYPE);
    model.setRequestedTokenType(TokenExchangeChecks.ACCESS_TOKEN_TYPE);
    model.setResource(resource);
    model.setScope(scope);
    model.setActorToken(" ");
    model.setActorTokenType(TokenExchangeChecks.ACCESS_TOKEN_TYPE);
    return model;
  }

  private static String token(final Map<String, Object> claims) throws Exception {
    return new PlainJWT(JWTClaimsSet.parse(claims)).serialize();
  }

  private static String tokenResponse(final String accessToken) {
    return """
        {"access_token":"%s","issued_token_type":"%s","token_type":"Bearer","expires_in":300,"scope":"api2"}"""
        .formatted(accessToken, TokenExchangeChecks.ACCESS_TOKEN_TYPE);
  }

  private void recordBody(final ClientHttpRequest request) {
    this.sentBodies.add(((MockClientHttpRequest) request).getBodyAsString());
  }
}
