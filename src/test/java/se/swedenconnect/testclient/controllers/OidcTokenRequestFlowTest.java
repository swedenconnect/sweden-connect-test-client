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
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.thymeleaf.standard.serializer.StandardJavaScriptSerializer;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.oidc.OidcRp;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.startsWith;
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
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.ACCESS_TOKEN;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.OP;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.RP;
import static se.swedenconnect.testclient.controllers.UserInfoTestSupport.TOKEN_ENDPOINT;

/**
 * Tests for the token request that {@link OidcController} sends when the OP redirects back with an authorization code
 * - its settings, how it is recorded, and how a failed token request is reported.
 *
 * @author Martin Lindström
 */
class OidcTokenRequestFlowTest {

  private static final String ERROR_BODY =
      "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed\"}";

  private MockHttpSession session;
  private MockRestServiceServer server;
  private OidcController controller;
  private OidcRp rp;
  private final List<String> sentBodies = new ArrayList<>();

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    this.controller = new OidcController(this.session, builder.build());
    this.rp = UserInfoTestSupport.rp();
    UserInfoTestSupport.authenticationInSession(this.session, this.rp);
    // Only the token request is of interest
    this.session.setAttribute(OidcController.SESSION_NAME_CALL_USERINFO, false);
    this.session.setAttribute(AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE,
        Pair.of(CodeChallengeMethod.S256, new CodeVerifier("0123456789012345678901234567890123456789abc")));
  }

  // The request that is sent

  @Test
  void withoutSettingsTheDefaultRequestIsSent() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header(HttpHeaders.CONTENT_TYPE, startsWith(MediaType.APPLICATION_FORM_URLENCODED_VALUE)))
        .andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
        .andExpect(this::recordBody)
        .andRespond(withSuccess(UserInfoTestSupport.tokenResponse(), MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    final Map<String, List<String>> sent = this.sentParameters();
    assertEquals(List.of("authorization_code"), sent.get("grant_type"));
    assertEquals(List.of("code"), sent.get("code"));
    assertEquals(List.of(RP + "/redirect"), sent.get("redirect_uri"));
    assertEquals(List.of("0123456789012345678901234567890123456789abc"), sent.get("code_verifier"));
    assertEquals(List.of(TokenRequestParameterModel.JWT_BEARER_ASSERTION_TYPE), sent.get("client_assertion_type"));
    assertEquals(6, sent.size());

    final JWSObject assertion = JWSObject.parse(sent.get("client_assertion").get(0));
    final PkiCredential rpCredential = this.rp.getCredentials().getCredentialForSigning();
    assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) rpCredential.getPublicKey())));
    assertEquals(RP, assertion.getPayload().toJSONObject().get("iss"));
    assertEquals(OP, assertion.getPayload().toJSONObject().get("aud"));

    // The request is recorded as it was sent
    final SentTokenRequest recorded = response.getTokenRequest();
    assertEquals("POST", recorded.method());
    assertEquals(TOKEN_ENDPOINT, recorded.url());
    assertEquals(sent.keySet(), recorded.parameters().keySet());
    assertEquals(sent.get("client_assertion").get(0), recorded.parameters().get("client_assertion"));
    assertEquals(RP, recorded.clientAssertion().claims().get("sub"));

    // The result is as before
    assertNull(response.getTokenError());
    assertNull(response.getErrors());
    assertEquals(ACCESS_TOKEN, response.getAccessToken());
    assertEquals("196911292032", response.getIdTokenClaims().get(UserInfoTestSupport.PERSONAL_IDENTITY_NUMBER));
  }

  @Test
  void theSettingsOfTheAuthenticationRequestAreUsed() throws Exception {
    final TokenRequestParameterModel settings = this.defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_BASIC);
    settings.getClientSecret().setValue("secret");
    settings.getClientAssertionType().setValuePresent(false);
    settings.getClientAssertion().setValuePresent(false);
    settings.getCodeVerifier().setValuePresent(false);
    settings.getCode().setValue("typed-code");
    this.session.setAttribute(OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS,
        new OidcController.TokenRequestSettings(settings, null));

    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(header(HttpHeaders.AUTHORIZATION,
            TokenRequestFactory.basicAuthorization(RP, "secret")))
        .andExpect(this::recordBody)
        .andRespond(withSuccess(UserInfoTestSupport.tokenResponse(), MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    final Map<String, List<String>> sent = this.sentParameters();
    assertEquals(List.of("grant_type", "code", "redirect_uri"), List.copyOf(sent.keySet()));
    assertEquals(List.of("typed-code"), sent.get("code"));
    assertEquals(TokenRequestFactory.basicAuthorization(RP, "secret"),
        response.getTokenRequest().headers().get(HttpHeaders.AUTHORIZATION));
    assertNull(response.getTokenRequest().clientAssertion());
    assertEquals(ACCESS_TOKEN, response.getAccessToken());
  }

  @Test
  void thePrivateKeyJwtAssertionIsSignedWithTheKeySelectedUnderKeyOptions() throws Exception {
    final RSAKey other = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    final PkiCredential otherCredential = new BasicCredential(other.toPublicKey(), other.toPrivateKey());
    final String otherKid = new JwkTransformerFunction().serializable().apply(otherCredential).getKeyID();
    this.session.setAttribute(OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS,
        new OidcController.TokenRequestSettings(null, Pair.of(otherKid, otherCredential)));
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andExpect(this::recordBody)
        .andRespond(withSuccess(UserInfoTestSupport.tokenResponse(), MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    final JWSObject assertion = JWSObject.parse(this.sentParameters().get("client_assertion").get(0));
    assertEquals(otherKid, assertion.getHeader().getKeyID());
    assertTrue(assertion.verify(new RSASSAVerifier(other.toRSAPublicKey())));
    assertEquals(otherKid, response.getTokenRequest().clientAssertion().header().get("kid"));
  }

  // Token requests that are not sent

  @Test
  void anUnavailableKeyOptionsKeyGivesATokenEndpointErrorAndNoRequest() throws Exception {
    this.session.setAttribute(OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS,
        new OidcController.TokenRequestSettings(null, Pair.of("unknown-kid", null)));
    this.server.expect(never(), anything());

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertNotSentError(response, "the signing key selected under Key options is not available");
  }

  @Test
  void anAssertionThatCannotBeBuiltGivesATokenEndpointErrorAndNoRequest() throws Exception {
    final TokenRequestParameterModel settings = this.defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_JWT);
    settings.getClientSecret().setValue("short");
    this.session.setAttribute(OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS,
        new OidcController.TokenRequestSettings(settings, null));
    this.server.expect(never(), anything());

    final OIDCResponse response = this.redirect();

    this.server.verify();
    assertNotSentError(response, "The client assertion could not be built: ");
  }

  private static void assertNotSentError(final OIDCResponse response, final String reason) {
    assertNull(response.getTokenRequest());
    assertNull(response.getOpError());
    assertNotNull(response.getAuthorizationRequest());
    final TokenEndpointError error = response.getTokenError();
    assertTrue(error.getMessage().startsWith("The token request was not sent to the token endpoint " + TOKEN_ENDPOINT),
        error.getMessage());
    assertTrue(error.getMessage().contains(reason), error.getMessage());
    assertNull(error.getHttpStatus());
    assertEquals(List.of(error.getMessage()), response.getErrors());
    assertNull(response.getAccessToken());
  }

  // Failed token requests

  @ParameterizedTest
  @ValueSource(ints = { 400, 401, 403, 500, 503 })
  void anErrorStatusIsReportedWithTheErrorAndTheTokenRequest(final int status) throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withStatus(HttpStatus.valueOf(status)).contentType(MediaType.APPLICATION_JSON).body(ERROR_BODY));

    final OIDCResponse response = this.redirect();

    this.server.verify();
    final TokenEndpointError error = response.getTokenError();
    assertEquals("The token endpoint %s answered the token request with an error".formatted(TOKEN_ENDPOINT),
        error.getMessage());
    assertEquals(status, error.getHttpStatus());
    assertEquals("invalid_client", error.getError());
    assertEquals("Client authentication failed", error.getErrorDescription());
    assertEquals(ERROR_BODY, error.getBody());
    assertEquals(List.of(error.getMessage(), "HTTP status: " + status, "error: invalid_client",
        "error_description: Client authentication failed", "Response body: " + ERROR_BODY), response.getErrors());
    assertFailedTokenRequest(response);
  }

  @Test
  void anErrorStatusWithoutAJsonBodyIsReported() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withStatus(HttpStatus.BAD_GATEWAY).contentType(MediaType.TEXT_HTML).body("<html>Bad</html>"));

    final OIDCResponse response = this.redirect();

    final TokenEndpointError error = response.getTokenError();
    assertEquals(502, error.getHttpStatus());
    assertNull(error.getError());
    assertNull(error.getErrorDescription());
    assertEquals("<html>Bad</html>", error.getBody());
    assertEquals(List.of(error.getMessage(), "HTTP status: 502", "Response body: <html>Bad</html>"),
        response.getErrors());
    assertFailedTokenRequest(response);
  }

  @Test
  void anErrorStatusWithoutABodyIsReported() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT)).andRespond(withStatus(HttpStatus.UNAUTHORIZED));

    final OIDCResponse response = this.redirect();

    assertEquals(401, response.getTokenError().getHttpStatus());
    assertNull(response.getTokenError().getBody());
    assertEquals(2, response.getErrors().size());
    assertFailedTokenRequest(response);
  }

  @Test
  void aNetworkErrorIsReported() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT)).andRespond(withException(new IOException("Connection refused")));

    final OIDCResponse response = this.redirect();

    final TokenEndpointError error = response.getTokenError();
    assertTrue(error.getMessage().startsWith(
        "The token request to %s failed - no response was received: ".formatted(TOKEN_ENDPOINT)), error.getMessage());
    assertTrue(error.getMessage().contains("Connection refused"), error.getMessage());
    assertNull(error.getHttpStatus());
    assertNull(error.getBody());
    assertEquals(List.of(error.getMessage()), response.getErrors());
    assertFailedTokenRequest(response);
  }

  @ParameterizedTest
  @ValueSource(strings = { "garbage", "[1, 2]", "\"a string\"", "" })
  void aSuccessResponseThatCannotBeReadIsReported(final String body) throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT)).andRespond(withSuccess(body, MediaType.APPLICATION_JSON));

    final OIDCResponse response = this.redirect();

    final TokenEndpointError error = response.getTokenError();
    assertEquals("The token endpoint %s answered the token request, but the response could not be read as a JSON"
        .formatted(TOKEN_ENDPOINT) + " object", error.getMessage());
    assertEquals(200, error.getHttpStatus());
    assertEquals(body.isEmpty() ? null : body, error.getBody());
    assertFailedTokenRequest(response);
  }

  private void assertFailedTokenRequest(final OIDCResponse response) {
    // Not an error in the authorization response
    assertNull(response.getOpError());
    assertNotNull(response.getAuthorizationRequest());
    assertNotNull(response.getTokenRequest());
    assertEquals(TOKEN_ENDPOINT, response.getTokenRequest().url());
    assertTrue(response.getTokenRequest().parameters().containsKey("client_assertion"));
    assertNull(response.getAccessToken());
    assertNull(response.getResponse());
    assertNull(response.getResponseParameters());
    assertNull(this.session.getAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS));
  }

  @Test
  void aTokenResponseThatCannotBeProcessedIsNoLongerReportedAsAnOpError() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withSuccess(UserInfoTestSupport.tokenResponse(), MediaType.APPLICATION_JSON));

    // Without iss the response parameters cannot be recorded
    this.controller.handleRedirection(new MockHttpServletRequest(), "rp", null, null, "state", null, "code");
    final OIDCResponse response =
        (OIDCResponse) this.session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);

    assertNull(response.getOpError());
    assertNull(response.getTokenError());
    assertTrue(response.getErrors().get(0).startsWith(
        "The token response from %s could not be processed".formatted(TOKEN_ENDPOINT)), response.getErrors().get(0));
    assertNotNull(response.getTokenRequest());
    assertEquals(ACCESS_TOKEN, response.getResponse().get("access_token"));
  }

  @Test
  void anErrorInTheAuthorizationResponseSendsNoTokenRequest() throws Exception {
    this.server.expect(never(), anything());

    this.controller.handleRedirection(new MockHttpServletRequest(), "rp", "access_denied", "Denied", "state", OP,
        null);
    final OIDCResponse response =
        (OIDCResponse) this.session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);

    this.server.verify();
    assertTrue(response.getOpError());
    assertNull(response.getTokenRequest());
    assertNull(response.getTokenError());
  }

  // What reaches the page

  @Test
  void theTokenRequestAndTheErrorReachThePage() throws Exception {
    this.server.expect(requestTo(TOKEN_ENDPOINT))
        .andRespond(withStatus(HttpStatus.UNAUTHORIZED).contentType(MediaType.APPLICATION_JSON).body(ERROR_BODY));
    final OIDCResponse response = this.redirect();

    final StringWriter written = new StringWriter();
    new StandardJavaScriptSerializer(true).serializeValue(response, written);
    final JsonNode page = JsonMapper.builder().build().readTree(written.toString());

    final JsonNode tokenRequest = page.get("tokenRequest");
    assertEquals("POST", tokenRequest.get("method").asString());
    assertEquals(TOKEN_ENDPOINT, tokenRequest.get("url").asString());
    assertTrue(tokenRequest.get("headers").has(HttpHeaders.CONTENT_TYPE));
    assertEquals("authorization_code", tokenRequest.get("parameters").get("grant_type").asString());
    assertEquals(RP, tokenRequest.get("client_assertion").get("claims").get("iss").asString());
    assertTrue(tokenRequest.get("client_assertion").get("header").has("kid"));

    final JsonNode tokenError = page.get("tokenError");
    assertEquals(401, tokenError.get("http_status").asInt());
    assertEquals("invalid_client", tokenError.get("error").asString());
    assertEquals("Client authentication failed", tokenError.get("error_description").asString());
    assertFalse(page.has("op_error") && page.get("op_error").asBoolean());
    assertEquals(5, page.get("errors").size());
  }

  private TokenRequestParameterModel defaults() {
    return TokenRequestParameterModel.defaults(RP, RP + "/redirect", OP);
  }

  private void recordBody(final org.springframework.http.client.ClientHttpRequest request) {
    this.sentBodies.add(((MockClientHttpRequest) request).getBodyAsString());
  }

  private Map<String, List<String>> sentParameters() {
    assertEquals(1, this.sentBodies.size());
    return URLUtils.parseParameters(this.sentBodies.get(0));
  }

  private OIDCResponse redirect() throws Exception {
    final String view = this.controller.handleRedirection(new MockHttpServletRequest(), "rp", null, null, "state",
        OP, "code").getViewName();
    assertEquals("redirect:/", view);
    return (OIDCResponse) this.session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);
  }
}
