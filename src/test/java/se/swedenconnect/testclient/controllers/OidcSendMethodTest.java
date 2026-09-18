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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.client.RestClient;
import org.thymeleaf.standard.serializer.StandardJavaScriptSerializer;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.StringWriter;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Tests for sending the OIDC authentication request with GET or POST - what {@link OidcRestController} returns to the
 * browser and records as the sent request, and how {@link OidcController} reports the sent request back.
 *
 * @author Martin Lindström
 */
class OidcSendMethodTest {

  private static final String RP = "https://rp.example.com";
  private static final String OP = "https://op.example.com";
  private static final String AUTHORIZATION_ENDPOINT = "https://op.example.com/authorize?tenant=a";

  private MockHttpSession session;
  private OidcRestController restController;
  private OidcRp rp;
  private OidcOpRegistry registry;
  private OIDCOPMetadataFetcher fetcher;

  @BeforeEach
  void setUp() {
    this.session = new MockHttpSession();

    final OidcRp rp = Mockito.mock(OidcRp.class);
    this.rp = rp;
    Mockito.when(rp.getEntityId()).thenReturn(RP);
    final OidcOp op = OidcOp.builder()
        .entityId(OP)
        .authorizationEndpoint(AUTHORIZATION_ENDPOINT)
        .tokenEndpoint(OP + "/token")
        .build();
    final OidcOpRegistry registry = Mockito.mock(OidcOpRegistry.class);
    this.registry = registry;
    Mockito.when(registry.get(OP)).thenReturn(op);
    final OIDCOPMetadataFetcher fetcher = Mockito.mock(OIDCOPMetadataFetcher.class);
    this.fetcher = fetcher;
    Mockito.when(fetcher.getOPJWKS(op)).thenReturn(new JWKSet());

    this.restController = new OidcRestController(
        List.of(rp), registry, this.session, fetcher, null, null, Mockito.mock(RestClient.class));
  }

  @Test
  void getReturnsTheRequestUrlWithParametersInTheQueryString() throws Exception {
    final OidcRestController.OIDCAuthnRequestModel sent =
        this.restController.generateAuthnRequest(model(), SentAuthorizationRequest.Method.GET);

    Assertions.assertEquals("GET", sent.getMethod());
    Assertions.assertNull(sent.getParameters());
    Assertions.assertTrue(sent.getUrl().startsWith(AUTHORIZATION_ENDPOINT + "&"), sent.getUrl());
    final AuthenticationRequest authRequest = (AuthenticationRequest) this.session.getAttribute("auth_request");
    final Map<String, List<String>> query = URLUtils.parseParameters(URI.create(sent.getUrl()).getRawQuery());
    Assertions.assertEquals(List.of("a"), query.get("tenant"));
    Assertions.assertEquals(List.of(authRequest.getState().getValue()), query.get("state"));
  }

  @Test
  void postReturnsTheEndpointAndTheParametersAsFormParameters() throws Exception {
    final OidcRestController.OIDCAuthnRequestModel sent =
        this.restController.generateAuthnRequest(model(), SentAuthorizationRequest.Method.POST);

    Assertions.assertEquals("POST", sent.getMethod());
    Assertions.assertEquals(AUTHORIZATION_ENDPOINT, sent.getUrl());
    final AuthenticationRequest authRequest = (AuthenticationRequest) this.session.getAttribute("auth_request");
    final AuthorizationParameterResolver resolver = new AuthorizationParameterResolver(model(), false, (n, v) -> {
    });
    Assertions.assertEquals(AuthorizationRequestCustomizer.toParameters(authRequest, resolver), sent.getParameters());
    Assertions.assertFalse(sent.getParameters().containsKey("tenant"));
  }

  @ParameterizedTest
  @EnumSource(SentAuthorizationRequest.Method.class)
  void sentRequestIsRecordedWithTheMethodUsed(final SentAuthorizationRequest.Method method) throws Exception {
    final OidcRestController.OIDCAuthnRequestModel sent = this.restController.generateAuthnRequest(model(), method);

    final SentAuthorizationRequest recorded =
        (SentAuthorizationRequest) this.session.getAttribute(OidcController.SESSION_NAME_SENT_AUTH_REQUEST);
    Assertions.assertEquals(new SentAuthorizationRequest(method, sent.getUrl(), sent.getParameters()), recorded);
  }

  @ParameterizedTest
  @EnumSource(SentAuthorizationRequest.Method.class)
  void opErrorReportsTheSentRequestWithTheMethodUsed(final SentAuthorizationRequest.Method method) throws Exception {
    this.restController.generateAuthnRequest(model(), method);
    final SentAuthorizationRequest recorded =
        (SentAuthorizationRequest) this.session.getAttribute(OidcController.SESSION_NAME_SENT_AUTH_REQUEST);

    final OIDCResponse response = this.opError();

    Assertions.assertTrue(response.getOpError());
    Assertions.assertEquals(recorded, response.getAuthorizationRequest());
    Assertions.assertEquals(method, response.getAuthorizationRequest().method());
  }

  @Test
  void theCallUserInfoSettingIsRecordedForEachRequest() throws Exception {
    final OIDCAuthnRequestParameterModel model = model();
    this.session.setAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS, Map.of("sub", "earlier"));

    model.setCallUserInfo(false);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    Assertions.assertEquals(false, this.session.getAttribute(OidcController.SESSION_NAME_CALL_USERINFO));
    // The ID token of an earlier authentication does not belong to this request
    Assertions.assertNull(this.session.getAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS));

    // A later request is governed by its own setting
    model.setCallUserInfo(true);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    Assertions.assertEquals(true, this.session.getAttribute(OidcController.SESSION_NAME_CALL_USERINFO));

    // A request exported before the setting existed calls UserInfo
    model.setCallUserInfo(false);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    model.setCallUserInfo(null);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.POST);
    Assertions.assertEquals(true, this.session.getAttribute(OidcController.SESSION_NAME_CALL_USERINFO));
  }

  @Test
  void theTokenRequestSettingsAreRecordedForEachRequest() throws Exception {
    final OIDCAuthnRequestParameterModel model = model();
    final TokenRequestParameterModel settings = TokenRequestParameterModel.defaults(RP, RP + "/redirect", OP + "/token");
    settings.setAuthMethod(TokenRequestParameterModel.NONE);

    model.setTokenRequest(settings);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    Assertions.assertSame(settings, this.tokenRequestSettings().settings());
    // No key is selected under Key options - the RP's registered key is used
    Assertions.assertNull(this.tokenRequestSettings().keyOptionsSignKey());

    // A later request is governed by its own settings - a request exported before the settings existed has none
    model.setTokenRequest(null);
    this.restController.generateAuthnRequest(model, SentAuthorizationRequest.Method.POST);
    Assertions.assertNull(this.tokenRequestSettings().settings());
  }

  @Test
  void theKeyOptionsSigningKeyIsRecordedForTheTokenRequest() throws Exception {
    final RSAKey key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    final PkiCredential credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
    final String kid = new JwkTransformerFunction().serializable().apply(credential).getKeyID();
    final CredentialBundles bundles = Mockito.mock(CredentialBundles.class);
    Mockito.when(bundles.getRegisteredCredentials()).thenReturn(List.of("other"));
    Mockito.when(bundles.getCredential("other")).thenReturn(credential);
    final OidcRestController controller = new OidcRestController(
        List.of(this.rp), this.registry, this.session, this.fetcher, bundles, null, Mockito.mock(RestClient.class));
    final OIDCAuthnRequestParameterModel model = model();

    model.getKeys().setSignKey(kid);
    controller.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    Assertions.assertEquals(kid, this.tokenRequestSettings().keyOptionsSignKey().getLeft());
    Assertions.assertSame(credential, this.tokenRequestSettings().keyOptionsSignKey().getRight());
    Assertions.assertSame(credential, this.tokenRequestSettings().signingCredential(this.rp));

    model.getKeys().setSignKey("unknown");
    controller.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    Assertions.assertEquals("unknown", this.tokenRequestSettings().keyOptionsSignKey().getLeft());
    Assertions.assertNull(this.tokenRequestSettings().signingCredential(this.rp));
  }

  private OidcController.TokenRequestSettings tokenRequestSettings() {
    return (OidcController.TokenRequestSettings) this.session.getAttribute(
        OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS);
  }

  @Test
  void unrecordedSentRequestIsReportedAsGet() throws Exception {
    this.restController.generateAuthnRequest(model(), SentAuthorizationRequest.Method.POST);
    this.session.removeAttribute(OidcController.SESSION_NAME_SENT_AUTH_REQUEST);

    final SentAuthorizationRequest reported = this.opError().getAuthorizationRequest();

    Assertions.assertEquals(SentAuthorizationRequest.Method.GET, reported.method());
    Assertions.assertNull(reported.parameters());
  }

  @Test
  void sentRequestReachesThePageWithMethodUrlAndParameters() throws Exception {
    this.restController.generateAuthnRequest(model(), SentAuthorizationRequest.Method.POST);
    final OIDCResponse response = this.opError();

    // The result is handed to the page by Thymeleaf's inline JavaScript serialization (sc-client.html)
    final StringWriter written = new StringWriter();
    new StandardJavaScriptSerializer(true).serializeValue(response, written);

    final JsonNode sent = JsonMapper.builder().build().readTree(written.toString()).get("authorizationRequest");
    Assertions.assertEquals("POST", sent.get("method").asString());
    Assertions.assertEquals(AUTHORIZATION_ENDPOINT, sent.get("url").asString());
    Assertions.assertEquals("state", sent.get("parameters").get("state").get(0).asString());
  }

  private OIDCResponse opError() throws Exception {
    new OidcController(this.session, Mockito.mock(RestClient.class)).handleRedirection(
        new MockHttpServletRequest(), "rp", "access_denied", "Denied", null, null, null);
    return (OIDCResponse) this.session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);
  }

  private static OIDCAuthnRequestParameterModel model() {
    return OIDCAuthnRequestParameterModel.builder()
        .op(OP)
        .rp(RP)
        .scope(new ModelParameter("openid", false, true))
        .requestBodyScope("openid")
        .requestMode("request")
        .redirectUri(new ModelParameter(RP + "/oidc/redirect/rp", false, true))
        .clientId(new ModelParameter(RP, false, true))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequestBody(false)
        // A fixed code challenge value so that the model gives the same request each time
        .advanced(fixedCodeVerifier(OidcRestController.createDefaultAdvancedOptions()))
        .keys(KeyOptionsParameterModel.builder().moduleEnabled(true).build())
        .userMessage(OidcRestController.createDefaultUserMessage())
        .signMessage(OidcRestController.createDefaultSignRequest("key"))
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter(RP, true, true))
            .audience(new ModelParameter(OP + "/token", true, true))
            .signRequest(false)
            .encryptRequest(false)
            .moduleEnabled(false)
            .build())
        .build();
  }

  private static AdvancedOptionsParamterModel fixedCodeVerifier(final AdvancedOptionsParamterModel advanced) {
    advanced.getState().setValue("state");
    advanced.getNonce().setValue("nonce");
    advanced.getCodeChallenge().setValue("0123456789012345678901234567890123456789abc");
    return advanced;
  }
}
