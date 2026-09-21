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

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.credentials.TestCredentials;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Tests for the signing keys that are offered under "Key options" and for the key a selection resolves to - the
 * request object, the sign request JWT and the {@code private_key_jwt} client assertion.
 *
 * @author Martin Lindström
 */
class OidcSigningKeySelectionTest {

  private static final String RP = "https://client.example.com/testrp1";
  private static final String OP = "https://op.example.com";
  private static final String REGISTERED = "[Registered Key]";

  private PkiCredential signing;
  private PkiCredential signing2;
  private PkiCredential bundleKey;
  private OidcOpRegistry registry;
  private OIDCOPMetadataFetcher fetcher;

  @BeforeEach
  void setUp() throws Exception {
    this.signing = TestCredentials.generate();
    this.signing2 = TestCredentials.generate();
    this.bundleKey = TestCredentials.generate();

    final OidcOp op = OidcOp.builder()
        .entityId(OP)
        .authorizationEndpoint(OP + "/authorize")
        .tokenEndpoint(OP + "/token")
        .build();
    this.registry = Mockito.mock(OidcOpRegistry.class);
    Mockito.when(this.registry.get(OP)).thenReturn(op);
    this.fetcher = Mockito.mock(OIDCOPMetadataFetcher.class);
    Mockito.when(this.fetcher.getOPJWKS(op)).thenReturn(new JWKSet());
  }

  @Test
  void bothRpKeysAreOfferedAsRegisteredAndThePrimaryIsPreselected() throws Exception {
    final OidcRp rp = this.rp(this.signing, this.signing2);
    final OIDCAuthnRequestParameterModel template =
        this.controller(rp, this.bundleKey).template(RP, OP, new MockHttpSession());

    final Map<String, String> offered = offered(template);
    Assertions.assertEquals(REGISTERED, offered.get(TestCredentials.keyId(this.signing)));
    Assertions.assertEquals(REGISTERED, offered.get(TestCredentials.keyId(this.signing2)));
    // A key that is not registered by the RP is offered, but not marked
    Assertions.assertNull(offered.get(TestCredentials.keyId(this.bundleKey)));
    Assertions.assertEquals(3, offered.size());

    // The primary signing key is the pre-selected one, for the request object as well as the sign request JWT
    Assertions.assertEquals(TestCredentials.keyId(this.signing), template.getKeys().getSignKey());
    Assertions.assertEquals(TestCredentials.keyId(this.signing), template.getSignMessage().getSignKey());
  }

  @Test
  void anRpSigningKeyConfiguredInPlaceIsOffered() throws Exception {
    // Neither of the RP's keys is reachable through a bundle
    final OidcRp rp = this.rp(this.signing, this.signing2);
    final OIDCAuthnRequestParameterModel template =
        this.controller(rp, this.bundleKey).template(RP, OP, new MockHttpSession());

    Assertions.assertTrue(offered(template).containsKey(TestCredentials.keyId(this.signing)));
    Assertions.assertTrue(offered(template).containsKey(TestCredentials.keyId(this.signing2)));
  }

  @Test
  void aKeyIsOfferedOnceHoweverManyWaysItIsReachable() throws Exception {
    final OidcRp rp = this.rp(this.signing, this.signing2);
    // The RP's primary key is also a bundle credential
    final OIDCAuthnRequestParameterModel template =
        this.controller(rp, this.signing, this.bundleKey).template(RP, OP, new MockHttpSession());

    final List<String> kids = template.getKeys().getSignKeys().stream().map(KeyModel::getKid).toList();
    Assertions.assertEquals(kids.stream().distinct().toList(), kids);
    Assertions.assertEquals(3, kids.size());
    Assertions.assertEquals(REGISTERED, offered(template).get(TestCredentials.keyId(this.signing)));
  }

  @Test
  void anRpWithoutSigning2OffersOnlyItsPrimaryKeyAsRegistered() throws Exception {
    final OidcRp rp = this.rp(this.signing, null);
    final OIDCAuthnRequestParameterModel template =
        this.controller(rp, this.bundleKey).template(RP, OP, new MockHttpSession());

    final Map<String, String> offered = offered(template);
    Assertions.assertEquals(2, offered.size());
    Assertions.assertEquals(REGISTERED, offered.get(TestCredentials.keyId(this.signing)));
    Assertions.assertNull(offered.get(TestCredentials.keyId(this.bundleKey)));
    Assertions.assertFalse(offered.containsKey(TestCredentials.keyId(this.signing2)));
  }

  @Test
  void theSelectedKeySignsTheRequestObjectAndTheSignRequestJwt() throws Exception {
    final OidcRp rp = this.rp(this.signing, this.signing2);
    final MockHttpSession session = new MockHttpSession();
    final OidcRestController controller = this.controller(session, rp, this.bundleKey);

    // The primary key by default ...
    final OIDCAuthnRequestParameterModel model = model(TestCredentials.keyId(this.signing));
    controller.generateAuthnRequest(model, SentAuthorizationRequest.Method.GET);
    assertSignedBy(this.signing, (SignedJWT) session.getAttribute("signed_jwt"));

    // ... and signing2 when it is selected
    final String kid2 = TestCredentials.keyId(this.signing2);
    final OIDCAuthnRequestParameterModel withSigning2 = model(kid2);
    controller.generateAuthnRequest(withSigning2, SentAuthorizationRequest.Method.GET);
    assertSignedBy(this.signing2, (SignedJWT) session.getAttribute("signed_jwt"));

    // The sign request JWT of the request URL is signed with the key selected for it
    final String url = ((SentAuthorizationRequest) session.getAttribute(
        OidcController.SESSION_NAME_SENT_AUTH_REQUEST)).url();
    final String signRequest =
        URLUtils.parseParameters(URI.create(url).getRawQuery()).get(OidcMessageSerializer.SIGN_REQUEST).get(0);
    assertSignedBy(this.signing2, SignedJWT.parse(signRequest));
  }

  @Test
  void theSelectedKeySignsTheClientAssertion() throws Exception {
    final OidcRp rp = this.rp(this.signing, this.signing2);
    final MockHttpSession session = new MockHttpSession();
    final OidcRestController controller = this.controller(session, rp, this.bundleKey);

    controller.generateAuthnRequest(model(TestCredentials.keyId(this.signing2)),
        SentAuthorizationRequest.Method.GET);

    final OidcController.TokenRequestSettings settings =
        (OidcController.TokenRequestSettings) session.getAttribute(
            OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS);
    Assertions.assertSame(this.signing2, settings.signingCredential(rp));

    // Without a selection the RP's primary signing credential is used
    final OIDCAuthnRequestParameterModel noSelection = model(TestCredentials.keyId(this.signing));
    noSelection.getKeys().setSignKey(null);
    // Nothing is signed when no key is selected
    noSelection.getRequestObject().setSignRequest(false);
    noSelection.getSignMessage().setSignJwt(false);
    controller.generateAuthnRequest(noSelection, SentAuthorizationRequest.Method.GET);
    final OidcController.TokenRequestSettings defaults =
        (OidcController.TokenRequestSettings) session.getAttribute(
            OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS);
    Assertions.assertSame(this.signing, defaults.signingCredential(rp));
  }

  private static void assertSignedBy(final PkiCredential credential, final SignedJWT jwt) throws Exception {
    Assertions.assertNotNull(jwt);
    Assertions.assertEquals(TestCredentials.keyId(credential), jwt.getHeader().getKeyID());
    Assertions.assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) credential.getPublicKey())));
  }

  /**
   * The offered signing keys as key ID to description, where the description is {@code null} for a key that is not
   * marked as a registered key of the RP.
   */
  private static Map<String, String> offered(final OIDCAuthnRequestParameterModel template) {
    final Map<String, String> keys = new LinkedHashMap<>();
    template.getKeys().getSignKeys().forEach(key -> keys.put(key.getKid(), key.getDescription()));
    return keys;
  }

  private OidcRp rp(final PkiCredential signing, final PkiCredential signing2) throws Exception {
    final ClientCredentials credentials =
        new ClientCredentials(signing, signing2, null, signing, null, signing, signing, signing);
    return new OidcRp(RP, "Test RP", "testrp1", credentials, "{ \"client_name\" : \"Test RP\" }",
        RP + "/redirect", false, RP + "/jwks", false);
  }

  private OidcRestController controller(final OidcRp rp, final PkiCredential... bundleCredentials) {
    return this.controller(new MockHttpSession(), rp, bundleCredentials);
  }

  private OidcRestController controller(final MockHttpSession session, final OidcRp rp,
      final PkiCredential... bundleCredentials) {
    final CredentialBundles bundles = Mockito.mock(CredentialBundles.class);
    final Map<String, PkiCredential> byName = java.util.stream.IntStream.range(0, bundleCredentials.length)
        .boxed()
        .collect(Collectors.toMap(i -> "bundle" + i, i -> bundleCredentials[i]));
    Mockito.when(bundles.getRegisteredCredentials()).thenReturn(List.copyOf(byName.keySet()));
    Mockito.when(bundles.getCredential(Mockito.anyString()))
        .thenAnswer(invocation -> byName.get((String) invocation.getArgument(0)));
    return new OidcRestController(
        List.of(rp), this.registry, session, this.fetcher, bundles, null, Mockito.mock(RestClient.class));
  }

  /**
   * The sign request of the request URL, signed with the supplied key.
   */
  private static SignatureParameterModel signRequestInRequestUrl(final String signKey) {
    final SignatureParameterModel signRequest = OidcRestController.createDefaultSignRequest(signKey);
    signRequest.setValuePresent(true);
    signRequest.setRequestBody(false);
    return signRequest;
  }

  /**
   * A request model whose request object is signed and whose sign request JWT is signed, both with the supplied key.
   */
  private static OIDCAuthnRequestParameterModel model(final String signKey) {
    final Function<String, ModelParameter> inRequestObject = value -> new ModelParameter(value, true, true);
    return OIDCAuthnRequestParameterModel.builder()
        .op(OP)
        .rp(RP)
        .scope(inRequestObject.apply("openid"))
        .requestBodyScope("openid")
        .requestMode("request")
        .redirectUri(inRequestObject.apply(RP + "/redirect"))
        .clientId(inRequestObject.apply(RP))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequestBody(false)
        .advanced(OidcRestController.createDefaultAdvancedOptions())
        .keys(KeyOptionsParameterModel.builder().signKey(signKey).moduleEnabled(true).build())
        .userMessage(OidcRestController.createDefaultUserMessage())
        .signMessage(signRequestInRequestUrl(signKey))
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter(RP, true, true))
            .audience(new ModelParameter(OP + "/token", true, true))
            .signRequest(true)
            .encryptRequest(false)
            .moduleEnabled(true)
            .build())
        .build();
  }

}
