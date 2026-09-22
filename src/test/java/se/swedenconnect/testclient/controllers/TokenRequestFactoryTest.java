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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link TokenRequestFactory}.
 *
 * @author Martin Lindström
 */
class TokenRequestFactoryTest {

  private static final String RP = "https://rp.example.com/rp";
  private static final String REDIRECT_URI = RP + "/redirect";
  private static final String OP_ISSUER = "https://op.example.com";
  private static final String TOKEN_ENDPOINT = OP_ISSUER + "/token";
  private static final String CODE = "the-code";
  private static final String VERIFIER = "the-code-verifier";
  private static final Instant NOW = Instant.ofEpochSecond(1789650256L);
  private static final String SECRET = "a-client-secret-that-is-long-enough-for-hs256";

  private static RSAKey key;
  private static PkiCredential credential;

  @BeforeAll
  static void createKey() throws Exception {
    key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
  }

  // The default request

  @Test
  void theDefaultsGiveTheRequestTheTestClientHasAlwaysSent() throws Exception {
    final SentTokenRequest request = create(defaults());

    assertEquals("POST", request.method());
    assertEquals(TOKEN_ENDPOINT, request.url());
    assertEquals(Map.of(
        HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded; charset=UTF-8",
        HttpHeaders.ACCEPT, "application/json"), request.headers());
    assertEquals(List.of("grant_type", "code", "redirect_uri", "code_verifier", "client_assertion_type",
        "client_assertion"), List.copyOf(request.parameters().keySet()));
    assertEquals("authorization_code", request.parameters().get("grant_type"));
    assertEquals(CODE, request.parameters().get("code"));
    assertEquals(REDIRECT_URI, request.parameters().get("redirect_uri"));
    assertEquals(VERIFIER, request.parameters().get("code_verifier"));
    assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        request.parameters().get("client_assertion_type"));

    final JWSObject assertion = JWSObject.parse(request.parameters().get("client_assertion"));
    assertEquals(JWSAlgorithm.RS256, assertion.getHeader().getAlgorithm());
    final String kid = new JwkTransformerFunction().serializable().apply(credential).getKeyID();
    assertEquals(kid, assertion.getHeader().getKeyID());
    assertEquals(new JwkTransformerFunction().serializable().apply(credential).toPublicJWK(),
        assertion.getHeader().getJWK());
    assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) credential.getPublicKey())));

    final JWTClaimsSet claims = JWTClaimsSet.parse(assertion.getPayload().toJSONObject());
    assertEquals(RP, claims.getIssuer());
    assertEquals(RP, claims.getSubject());
    assertEquals(List.of(OP_ISSUER), claims.getAudience());
    assertEquals(NOW.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
    assertEquals(NOW.getEpochSecond() + 300, claims.getExpirationTime().toInstant().getEpochSecond());
    assertNotNull(UUID.fromString(claims.getJWTID()));
    // A single audience is a string, as before
    assertEquals(OP_ISSUER, assertion.getPayload().toJSONObject().get("aud"));

    assertEquals(claims.toJSONObject(), request.clientAssertion().claims());
    assertEquals("RS256", request.clientAssertion().header().get("alg"));
    assertNull(request.clientAssertion().error());
  }

  @Test
  void eachAssertionGetsANewJti() throws Exception {
    assertFalse(create(defaults()).clientAssertion().claims().get("jti")
        .equals(create(defaults()).clientAssertion().claims().get("jti")));
  }

  @Test
  void withoutACodeVerifierTheParameterIsLeftOut() throws Exception {
    final SentTokenRequest request =
        TokenRequestFactory.create(defaults(), TOKEN_ENDPOINT, CODE, null, credential, NOW);

    assertFalse(request.parameters().containsKey("code_verifier"));
  }

  @Test
  void withoutACodeTheParameterIsLeftOut() throws Exception {
    final SentTokenRequest request =
        TokenRequestFactory.create(defaults(), TOKEN_ENDPOINT, null, VERIFIER, credential, NOW);

    assertFalse(request.parameters().containsKey("code"));
  }

  // Parameter rows

  @Test
  void anUncheckedRowIsNotSent() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getGrantType().setValuePresent(false);
    settings.getCode().setValuePresent(false);
    settings.getRedirectUri().setValuePresent(false);
    settings.getCodeVerifier().setValuePresent(false);
    settings.getClientAssertionType().setValuePresent(false);
    settings.getClientAssertion().setValuePresent(false);

    final SentTokenRequest request = create(settings);

    assertEquals(Map.of(), request.parameters());
    assertNull(request.clientAssertion());
  }

  @Test
  void typedValuesAreSentAsTheyAre() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getGrantType().setValue("refresh_token");
    settings.getCode().setValue("another-code");
    settings.getRedirectUri().setValue("");
    settings.getCodeVerifier().setValue("another verifier");
    settings.getClientAssertionType().setValue("urn:other");
    settings.getClientId().setValuePresent(true);
    settings.getClientId().setValue("other-client");
    settings.getClientSecret().setValuePresent(true);

    final Map<String, String> parameters = create(settings).parameters();

    assertEquals("refresh_token", parameters.get("grant_type"));
    assertEquals("another-code", parameters.get("code"));
    assertEquals("", parameters.get("redirect_uri"));
    assertEquals("another verifier", parameters.get("code_verifier"));
    assertEquals("urn:other", parameters.get("client_assertion_type"));
    assertEquals("other-client", parameters.get("client_id"));
    assertEquals("", parameters.get("client_secret"));
    assertEquals(List.of("grant_type", "code", "redirect_uri", "code_verifier", "client_id", "client_secret",
        "client_assertion_type", "client_assertion"), List.copyOf(parameters.keySet()));
  }

  @Test
  void aTypedClientAssertionIsSentInsteadOfTheBuiltOne() throws Exception {
    final String typed = new PlainJWT(new JWTClaimsSet.Builder().issuer("someone-else").build()).serialize();
    final TokenRequestParameterModel settings = defaults();
    settings.getClientAssertion().setValue(typed);
    // The claim rows are not used
    settings.getAssertionIss().setValue("not used");

    final SentTokenRequest request =
        TokenRequestFactory.create(settings, TOKEN_ENDPOINT, CODE, VERIFIER, null, NOW);

    assertEquals(typed, request.parameters().get("client_assertion"));
    assertEquals(Map.of("iss", "someone-else"), request.clientAssertion().claims());
    assertEquals(Map.of("alg", "none"), request.clientAssertion().header());
  }

  @ParameterizedTest
  @ValueSource(strings = { "not-a-jwt", "a.b.c", "eyJhbGciOiJub25lIn0.WzFd." })
  void aTypedClientAssertionThatCannotBeDecodedIsSentAndReported(final String typed) throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getClientAssertion().setValue(typed);

    final SentTokenRequest request = create(settings);

    assertEquals(typed, request.parameters().get("client_assertion"));
    assertNull(request.clientAssertion().header());
    assertNull(request.clientAssertion().claims());
    assertNotNull(request.clientAssertion().error());
  }

  @Test
  void anEncryptedTypedClientAssertionIsNotDecoded() throws Exception {
    final EncryptedJWT encrypted = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM),
        new JWTClaimsSet.Builder().issuer(RP).build());
    encrypted.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
    final TokenRequestParameterModel settings = defaults();
    settings.getClientAssertion().setValue(encrypted.serialize());

    final SentTokenRequest.ClientAssertion decoded = create(settings).clientAssertion();

    assertEquals("the client assertion is an encrypted JWT", decoded.error());
  }

  @ParameterizedTest
  @ValueSource(strings = { "client_secret_post", "client_secret_basic", "none" })
  void anEmptyClientAssertionIsLeftOutForMethodsWithoutAnAssertion(final String method) throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(method);

    final SentTokenRequest request = create(settings);

    assertFalse(request.parameters().containsKey("client_assertion"));
    assertNull(request.clientAssertion());
    // A checked client_assertion_type row is still sent
    assertTrue(request.parameters().containsKey("client_assertion_type"));
  }

  // Client assertion claims

  @Test
  void uncheckedClaimsAreLeftOutOfTheAssertion() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getAssertionIss().setValuePresent(false);
    settings.getAssertionSub().setValuePresent(false);
    settings.getAssertionAud().setValuePresent(false);
    settings.getAssertionIat().setValuePresent(false);
    settings.getAssertionJti().setValuePresent(false);
    settings.getAssertionExp().setValuePresent(false);

    final SentTokenRequest request = create(settings);

    assertEquals(Map.of(), request.clientAssertion().claims());
    assertTrue(JWSObject.parse(request.parameters().get("client_assertion"))
        .verify(new RSASSAVerifier((RSAPublicKey) credential.getPublicKey())));
  }

  @Test
  void typedClaimsAreUsedAsTheyAre() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getAssertionIss().setValue("https://other.example.com");
    settings.getAssertionSub().setValue("");
    settings.getAssertionAud().setValue("https://op.example.com");
    settings.getAssertionIat().setValue("1000");
    settings.getAssertionJti().setValue("same-jti");
    settings.getAssertionExp().setValue("tomorrow");

    final Map<String, Object> claims = create(settings).clientAssertion().claims();

    assertEquals("https://other.example.com", claims.get("iss"));
    assertEquals("", claims.get("sub"));
    assertEquals("https://op.example.com", claims.get("aud"));
    assertEquals(1000L, ((Number) claims.get("iat")).longValue());
    assertEquals("same-jti", claims.get("jti"));
    assertEquals("tomorrow", claims.get("exp"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "-5", "0", "1789650256", "999999999999999999" })
  void aTypedWholeNumberTimeIsSentAsANumber(final String typed) throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getAssertionExp().setValue(typed);

    final Object exp = create(settings).clientAssertion().claims().get("exp");

    assertTrue(exp instanceof Number, () -> "Not a number: " + exp);
    assertEquals(Long.parseLong(typed), ((Number) exp).longValue());
  }

  @ParameterizedTest
  @ValueSource(strings = { "1.5", "1e9", " 1000", "+1000", "9999999999999999999", "abc" })
  void anyOtherTypedTimeIsSentAsAString(final String typed) throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.getAssertionIat().setValue(typed);

    assertEquals(typed, create(settings).clientAssertion().claims().get("iat"));
  }

  @Test
  void privateKeyJwtWithoutTheSelectedKeyCannotBeBuilt() {
    final TokenRequestException e = assertThrows(TokenRequestException.class,
        () -> TokenRequestFactory.create(defaults(), TOKEN_ENDPOINT, CODE, VERIFIER, null, NOW));

    assertTrue(e.getMessage().startsWith("The client assertion could not be built"), e.getMessage());
  }

  // Client authentication methods

  @Test
  void clientSecretJwtSignsTheAssertionWithTheSecret() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_JWT);
    settings.getClientSecret().setValue(SECRET);

    // No private key is needed
    final SentTokenRequest request =
        TokenRequestFactory.create(settings, TOKEN_ENDPOINT, CODE, VERIFIER, null, NOW);

    final JWSObject assertion = JWSObject.parse(request.parameters().get("client_assertion"));
    assertEquals(Map.of("alg", "HS256"), assertion.getHeader().toJSONObject());
    assertTrue(assertion.verify(new MACVerifier(SECRET.getBytes(StandardCharsets.UTF_8))));
    assertEquals(RP, request.clientAssertion().claims().get("iss"));
    // The secret is only used for signing, since the client_secret row is unchecked
    assertFalse(request.parameters().containsKey("client_secret"));
    assertFalse(request.headers().containsKey(HttpHeaders.AUTHORIZATION));
  }

  @ParameterizedTest
  @ValueSource(strings = { "", "too-short-for-hs256" })
  void clientSecretJwtWithASecretTooShortCannotBeBuilt(final String secret) {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_JWT);
    settings.getClientSecret().setValue(secret);

    final TokenRequestException e = assertThrows(TokenRequestException.class, () -> create(settings));

    assertTrue(e.getMessage().startsWith("The client assertion could not be built: "), e.getMessage());
  }

  @Test
  void clientSecretJwtWithATypedAssertionNeedsNoSecret() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_JWT);
    settings.getClientAssertion().setValue("typed");

    assertEquals("typed", create(settings).parameters().get("client_assertion"));
  }

  @Test
  void clientSecretPostSendsTheCheckedClientRowsOnly() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_POST);
    settings.getClientId().setValuePresent(true);
    settings.getClientSecret().setValuePresent(true);
    settings.getClientSecret().setValue(SECRET);
    settings.getClientAssertionType().setValuePresent(false);
    settings.getClientAssertion().setValuePresent(false);

    final SentTokenRequest request = create(settings);

    assertEquals(RP, request.parameters().get("client_id"));
    assertEquals(SECRET, request.parameters().get("client_secret"));
    assertFalse(request.parameters().containsKey("client_assertion_type"));
    assertFalse(request.headers().containsKey(HttpHeaders.AUTHORIZATION));
  }

  @Test
  void clientSecretBasicSendsAnAuthorizationHeaderAlsoWhenTheRowsAreUnchecked() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_BASIC);
    settings.getClientId().setValue("s6BhdRkqt3");
    settings.getClientSecret().setValue("gX1fBat3bV");
    settings.getClientAssertionType().setValuePresent(false);
    settings.getClientAssertion().setValuePresent(false);

    final SentTokenRequest request = create(settings);

    // The example of RFC 6749, section 4.1.3
    assertEquals("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW", request.headers().get(HttpHeaders.AUTHORIZATION));
    assertFalse(request.parameters().containsKey("client_id"));
    assertFalse(request.parameters().containsKey("client_secret"));
  }

  @Test
  void clientSecretBasicAlsoSendsCheckedClientRows() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.CLIENT_SECRET_BASIC);
    settings.getClientId().setValuePresent(true);

    final SentTokenRequest request = create(settings);

    assertTrue(request.headers().containsKey(HttpHeaders.AUTHORIZATION));
    assertEquals(RP, request.parameters().get("client_id"));
  }

  @Test
  void theBasicCredentialsAreFormEncodedBeforeTheyAreJoined() {
    assertEquals("Basic " + java.util.Base64.getEncoder().encodeToString(
            "a+b%3Ac%2Fd:%C3%A9%26x%3D".getBytes(StandardCharsets.UTF_8)),
        TokenRequestFactory.basicAuthorization("a b:c/d", "é&x="));
    assertEquals("Basic Og==", TokenRequestFactory.basicAuthorization("", ""));
  }

  @Test
  void noneSendsNoClientAuthentication() throws Exception {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(TokenRequestParameterModel.NONE);
    settings.getClientId().setValuePresent(true);
    settings.getClientAssertionType().setValuePresent(false);
    settings.getClientAssertion().setValuePresent(false);

    final SentTokenRequest request = create(settings);

    assertEquals(List.of("grant_type", "code", "redirect_uri", "code_verifier", "client_id"),
        List.copyOf(request.parameters().keySet()));
    assertFalse(request.headers().containsKey(HttpHeaders.AUTHORIZATION));
  }

  @ParameterizedTest
  @ValueSource(strings = { "", "PRIVATE_KEY_JWT", "tls_client_auth" })
  void anUnknownMethodCannotBeBuilt(final String method) {
    final TokenRequestParameterModel settings = defaults();
    settings.setAuthMethod(method);

    final TokenRequestException e = assertThrows(TokenRequestException.class, () -> create(settings));

    assertEquals("Unknown client authentication method '%s'".formatted(method), e.getMessage());
  }

  // Defaults

  @Test
  void missingSettingsGetTheDefaults() throws Exception {
    assertEquals(create(defaults()).parameters().keySet(), create(TokenRequestParameterModel.withDefaults(null,
        defaults())).parameters().keySet());

    final TokenRequestParameterModel partial = new TokenRequestParameterModel();
    partial.setCode(new ModelParameter("typed-code", false, true));
    final TokenRequestParameterModel complete = TokenRequestParameterModel.withDefaults(partial, defaults());

    assertEquals(TokenRequestParameterModel.PRIVATE_KEY_JWT, complete.getAuthMethod());
    final SentTokenRequest request = create(complete);
    assertEquals("typed-code", request.parameters().get("code"));
    assertEquals(REDIRECT_URI, request.parameters().get("redirect_uri"));
    assertEquals(RP, request.clientAssertion().claims().get("sub"));
  }

  @Test
  void theDefaultRows() {
    final TokenRequestParameterModel defaults = defaults();

    assertEquals("private_key_jwt", defaults.getAuthMethod());
    assertEquals(false, defaults.getModuleEnabled());
    assertRow("authorization_code", true, defaults.getGrantType());
    assertRow("", true, defaults.getCode());
    assertRow(REDIRECT_URI, true, defaults.getRedirectUri());
    assertRow("", true, defaults.getCodeVerifier());
    assertRow(RP, false, defaults.getClientId());
    assertRow("", false, defaults.getClientSecret());
    assertRow("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", true, defaults.getClientAssertionType());
    assertRow("", true, defaults.getClientAssertion());
    assertRow(RP, true, defaults.getAssertionIss());
    assertRow(RP, true, defaults.getAssertionSub());
    assertRow(OP_ISSUER, true, defaults.getAssertionAud());
    assertRow("", true, defaults.getAssertionIat());
    assertRow("", true, defaults.getAssertionJti());
    assertRow("", true, defaults.getAssertionExp());
  }

  private static void assertRow(final String value, final boolean included, final ModelParameter row) {
    assertEquals(value, row.getValue());
    assertEquals(included, row.getValuePresent());
  }

  private static TokenRequestParameterModel defaults() {
    return TokenRequestParameterModel.defaults(RP, REDIRECT_URI, OP_ISSUER);
  }

  private static SentTokenRequest create(final TokenRequestParameterModel settings) throws TokenRequestException {
    return TokenRequestFactory.create(settings, TOKEN_ENDPOINT, CODE, VERIFIER, credential, NOW);
  }
}
