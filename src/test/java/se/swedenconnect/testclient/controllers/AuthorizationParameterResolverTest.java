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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Tests for {@link AuthorizationParameterResolver} - where PKCE, state and nonce are placed in an authentication
 * request, how the user message and sign request extensions are sent, the JWT:s of the request, and the outcome of the
 * request templates.
 *
 * @author Martin Lindström
 */
class AuthorizationParameterResolverTest {

  private static final String RP = "https://rp.example.com";
  private static final String REDIRECT_URI = "https://rp.example.com/oidc/redirect/rp";
  private static final String AUTHORIZATION_ENDPOINT = "https://op.example.com/authorize";
  private static final String OP_ISSUER = "https://op.example.com";

  private static final String USER_MESSAGE = "https://id.oidc.se/param/userMessage";
  private static final String SIGN_REQUEST = "https://id.oidc.se/param/signRequest";
  private static final String SCOPE_SIGN_APPROVAL = "https://id.oidc.se/scope/signApproval";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
  private static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";
  private static final String OTHER_CLIENT = "https://other.example.com";

  private static final JsonMapper MAPPER = JsonMapper.builder().build();

  /** The RP's registered signing key. */
  private static JWK key;

  /** Another signing key. */
  private static JWK otherKey;

  /** The OP's encryption key. */
  private static JWK encKey;

  private static Map<String, JWK> keys;

  @BeforeAll
  static void generateKey() throws Exception {
    key = new RSAKeyGenerator(2048).keyID("key").generate();
    otherKey = new ECKeyGenerator(Curve.P_256).keyID("other").generate();
    encKey = new RSAKeyGenerator(2048).keyID("enc").generate();
    keys = Map.of(key.getKeyID(), key, otherKey.getKeyID(), otherKey, encKey.getKeyID(), encKey);
  }

  @Test
  void pkceIsSentInUrlByDefault() throws Exception {
    final Result result = generate(defaultModel());

    Assertions.assertEquals("S256", result.url("code_challenge_method"));
    Assertions.assertNotNull(result.url("code_challenge"));
    Assertions.assertNull(result.claims(), "No request object expected");
    Assertions.assertEquals(challengeOf(result.verifier()), result.url("code_challenge"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "codeChallenge", "codeChallengeMethod" })
  void unselectingEitherPkceRowRemovesPkceFromUrl(final String row) throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    advanced(model, row).setValuePresent(false);

    final Result result = generate(model);

    Assertions.assertNull(result.url("code_challenge"));
    Assertions.assertNull(result.url("code_challenge_method"));
    Assertions.assertNull(result.verifier(), "No code verifier must be saved when PKCE is not sent");
  }

  @Test
  void pkceIsNotSentWhenRowsAreSelectedForDifferentLocations() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(advanced(model, "codeChallenge"), true, false);
    place(advanced(model, "codeChallengeMethod"), false, true);
    model.getAdvanced().getPrompt().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("code_challenge"));
    Assertions.assertNull(result.claims().getClaim("code_challenge"));
    Assertions.assertNull(result.verifier());
  }

  static Stream<Arguments> placements() {
    return Stream.of("state", "nonce", "codeChallenge")
        .flatMap(row -> Stream.of(
            Arguments.of(row, false, false),
            Arguments.of(row, true, false),
            Arguments.of(row, false, true),
            Arguments.of(row, true, true)));
  }

  @ParameterizedTest(name = "{0}: inRequest={1}, inRequestBody={2}")
  @MethodSource("placements")
  void serverGeneratedValueIsPlacedWhereTheBoxesSay(
      final String row, final boolean inRequest, final boolean inRequestBody) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(advanced(model, row), inRequest, inRequestBody);
    // A value not modified by the user, i.e., generated by the server
    advanced(model, row).setValue(null);
    if ("codeChallenge".equals(row)) {
      place(advanced(model, "codeChallengeMethod"), true, true);
    }
    // Make sure there is a request object even if the tested value is not placed in it
    model.getAdvanced().getPrompt().setRequestBody(true);

    final Result result = generate(model);

    final String claimName = "codeChallenge".equals(row) ? "code_challenge" : row;
    final String inUrl = result.url(claimName);
    final String inBody = (String) result.claims().getClaim(claimName);

    Assertions.assertEquals(inRequest, inUrl != null, "In URL");
    Assertions.assertEquals(inRequestBody, inBody != null, "In request object");
    if (inRequest && inRequestBody) {
      Assertions.assertEquals(inUrl, inBody, "Same value in URL and request object");
    }
    if ("codeChallenge".equals(row)) {
      Assertions.assertEquals(inRequest || inRequestBody, result.verifier() != null);
      if (result.verifier() != null) {
        final String challenge = challengeOf(result.verifier());
        Assertions.assertEquals(inRequest ? challenge : null, inUrl);
        Assertions.assertEquals(inRequestBody ? challenge : null, inBody);
      }
    }
  }

  @Test
  void userModifiedServerGeneratedValueIsUsed() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getAdvanced().getState(), true, true);
    model.getAdvanced().getState().setValue("my-state");

    final Result result = generate(model);

    Assertions.assertEquals("my-state", result.url("state"));
    Assertions.assertEquals("my-state", result.claims().getClaim("state"));
  }

  @Test
  void codeVerifierFromEarlierRequestIsNotReused() throws Exception {
    final Map<String, Object> session = new HashMap<>();
    final Result first = generate(defaultModel(), session);

    final OIDCAuthnRequestParameterModel model = defaultModel();
    model.getAdvanced().getCodeChallenge().setValuePresent(false);
    session.remove(AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE);
    final Result second = generate(model, session);
    Assertions.assertNull(second.url("code_challenge"));

    final Result third = generate(defaultModel(), session);
    Assertions.assertNotEquals(first.verifier().getValue(), third.verifier().getValue());
    Assertions.assertEquals(challengeOf(third.verifier()), third.url("code_challenge"));
  }

  @Test
  void templatesUseOnlyKnownParameterProperties() throws Exception {
    final Set<String> known = Set.of("value", "valuePresent", "requestBody");
    for (final JsonNode template : templates()) {
      final JsonNode advanced = template.path("advanced");
      advanced.properties().stream()
          .filter(e -> e.getValue().isObject())
          .forEach(e -> e.getValue().propertyNames().forEach(name -> Assertions.assertTrue(known.contains(name),
              "%s: unknown property '%s' in advanced.%s".formatted(template.get("name").asString(), name,
                  e.getKey()))));
    }
  }

  @ParameterizedTest
  @ValueSource(strings = { "Request Object (minimal)", "User Message Hidden", "Sign Hidden" })
  void requestObjectTemplatesPlaceStateNonceAndPkceInRequestObjectOnly(final String name) throws Exception {
    final OIDCAuthnRequestParameterModel model = applyTemplate(defaultModel(), template(name));

    final Result result = generate(model);

    final Map<String, List<String>> url = result.parameters();
    for (final String parameter : List.of("state", "nonce", "code_challenge", "code_challenge_method")) {
      Assertions.assertFalse(url.containsKey(parameter), parameter + " must not be in the URL");
    }
    Assertions.assertEquals(List.of("code"), url.get("response_type"));
    Assertions.assertTrue(url.containsKey("request"));

    final JWTClaimsSet claims = result.claims();
    Assertions.assertNotNull(claims.getClaim("state"));
    Assertions.assertNotNull(claims.getClaim("nonce"));
    Assertions.assertEquals("code", claims.getClaim("response_type"));
    Assertions.assertEquals(RP, claims.getClaim("client_id"));
    Assertions.assertEquals(REDIRECT_URI, claims.getClaim("redirect_uri"));
    Assertions.assertEquals(RP, claims.getIssuer());
    Assertions.assertEquals(template(name).get("scope").get("value").asString(), claims.getClaim("scope"));
    Assertions.assertEquals(template(name).get("scope").get("value").asString(), result.url("scope"));
    Assertions.assertEquals("S256", claims.getClaim("code_challenge_method"));
    Assertions.assertEquals(challengeOf(result.verifier()), claims.getClaim("code_challenge"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "Basic", "Natural Person Info (LoA3)", "Natural Person Number (LoA3)",
      "Natural Person Org ID (LoA3)" })
  void templatesWithoutAdvancedOptionsKeepPkceDefault(final String name) throws Exception {
    final OIDCAuthnRequestParameterModel model = applyTemplate(defaultModel(), template(name));

    final Result result = generate(model);

    Assertions.assertEquals("S256", result.url("code_challenge_method"));
    Assertions.assertEquals(challengeOf(result.verifier()), result.url("code_challenge"));
  }

  // The prompt parameter, which may hold several values (OpenID Connect Core 1.0, section 3.1.2.1)

  @Test
  void theDefaultPromptIsSentInTheUrl() throws Exception {
    final Result result = generate(defaultModel());

    Assertions.assertEquals("login", result.url("prompt"));
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "login",
      // Several values, sent in the order they were added
      "login consent",
      "consent login",
      "none login consent select_account",
      // Values that break the specification are sent as they are
      "none login",
      "login login",
      "unknown",
      "login urn:example:prompt",
      "consent NONE" })
  void thePromptValueIsSentAsItWasBuilt(final String value) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, "prompt", true, true);
    model.getAdvanced().getPrompt().setValue(value);

    final Result result = generate(model);

    Assertions.assertEquals(value, result.url("prompt"), "In URL");
    Assertions.assertEquals(value, result.claims().getClaim("prompt"), "In request object");
    // The value is sent the same way with GET and with POST
    Assertions.assertEquals(List.of(value), result.post().parameters().get("prompt"));
    Assertions.assertTrue(result.get().url().contains("prompt=" + URLEncoder.encode(value, StandardCharsets.UTF_8)),
        result.get().url());
  }

  @ParameterizedTest
  @ValueSource(strings = { "", " ", "   " })
  void aPromptWithoutValuesIsNotSent(final String value) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, "prompt", true, true);
    model.getAdvanced().getPrompt().setValue(value);
    // Make sure there is a request object even though the prompt is not placed in it
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertFalse(result.parameters().containsKey("prompt"), "In URL");
    Assertions.assertNull(result.claims().getClaim("prompt"), "In request object");
  }

  @Test
  void thePromptOfTheUrlAndOfTheRequestObjectAreTheSameValue() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, "prompt", true, false);
    model.getAdvanced().getPrompt().setValue("login consent");
    model.getAdvanced().getState().setRequestBody(true);

    final Result inUrlOnly = generate(model);

    Assertions.assertEquals("login consent", inUrlOnly.url("prompt"));
    Assertions.assertNull(inUrlOnly.claims().getClaim("prompt"));

    placeRow(model, "prompt", false, true);
    final Result inBodyOnly = generate(model);

    Assertions.assertFalse(inBodyOnly.parameters().containsKey("prompt"));
    Assertions.assertEquals("login consent", inBodyOnly.claims().getClaim("prompt"));
  }

  // The claims parameter, where a claim may be requested as essential with a value (OpenID Connect Core 1.0,
  // section 5.5.1)

  @Test
  void aClaimIsRequestedAsEssentialWithItsValue() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    final Map<String, Object> idTokenClaims = new HashMap<>();
    idTokenClaims.put("essentialWithValue", Map.of("essential", true, "value", "a"));
    idTokenClaims.put("essentialWithValues", Map.of("essential", true, "values", List.of("a", "b")));
    idTokenClaims.put("essentialOnly", Map.of("essential", true));
    idTokenClaims.put("valueOnly", Map.of("value", "a"));
    // A claim requested without "essential" and without a value
    idTokenClaims.put("nothing", null);
    model.setClaims(Map.of("id_token", idTokenClaims,
        "userinfo", Map.of("essentialWithValue", Map.of("essential", true, "value", "a"))));
    model.setClaimInRequest(true);

    final Result result = generate(model);

    final JsonNode idToken = JsonMapper.builder().build().readTree(result.url("claims")).get("id_token");
    Assertions.assertTrue(idToken.get("essentialWithValue").get("essential").asBoolean());
    Assertions.assertEquals("a", idToken.get("essentialWithValue").get("value").asString());
    Assertions.assertTrue(idToken.get("essentialWithValues").get("essential").asBoolean());
    Assertions.assertEquals(List.of("a", "b"),
        idToken.get("essentialWithValues").get("values").valueStream().map(JsonNode::asString).toList());
    Assertions.assertEquals(Set.of("essential"), Set.copyOf(idToken.get("essentialOnly").propertyNames()));
    Assertions.assertEquals(Set.of("value"), Set.copyOf(idToken.get("valueOnly").propertyNames()));
    Assertions.assertTrue(idToken.get("nothing").isNull());

    final JsonNode userInfo = JsonMapper.builder().build().readTree(result.url("claims")).get("userinfo");
    Assertions.assertTrue(userInfo.get("essentialWithValue").get("essential").asBoolean());
    Assertions.assertEquals("a", userInfo.get("essentialWithValue").get("value").asString());
  }

  @Test
  void anEssentialClaimWithAValueIsAlsoKeptInTheRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.setClaimInRequestBody(true);
    model.setClaims(Map.of("id_token", Map.of("birthdate", Map.of("essential", true, "value", "1969-11-29"))));

    final Result result = generate(model);

    Assertions.assertNull(result.url("claims"), "In URL");
    final Map<String, Object> claims = (Map<String, Object>) result.claims().getClaim("claims");
    final Map<String, Object> birthdate =
        (Map<String, Object>) ((Map<String, Object>) claims.get("id_token")).get("birthdate");
    Assertions.assertEquals(true, birthdate.get("essential"));
    Assertions.assertEquals("1969-11-29", birthdate.get("value"));
  }

  static Stream<Arguments> rowPlacements() {
    return Stream.of("client_id", "redirect_uri", "scope", "response_type", "acr_values", "prompt", "login_hint",
            USER_MESSAGE, SIGN_REQUEST)
        .flatMap(row -> Stream.of(
            Arguments.of(row, false, false),
            Arguments.of(row, true, false),
            Arguments.of(row, false, true),
            Arguments.of(row, true, true)));
  }

  @ParameterizedTest(name = "{0}: inRequest={1}, inRequestBody={2}")
  @MethodSource("rowPlacements")
  void parameterIsPlacedWhereTheBoxesSay(
      final String row, final boolean inRequest, final boolean inRequestBody) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, row, inRequest, inRequestBody);
    // Make sure there is a request object even if the tested parameter is not placed in it
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertEquals(inRequest, result.parameters().containsKey(row), "In URL");
    Assertions.assertEquals(inRequestBody, result.claims().getClaim(row) != null, "In request object");
  }

  @Test
  void parametersRequiredByRequestLibraryCanBeLeftOutOfUrlWithoutRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    for (final String row : List.of("client_id", "redirect_uri", "scope", "response_type")) {
      placeRow(model, row, false, false);
    }

    final Result result = generate(model);

    Assertions.assertNull(result.claims());
    for (final String parameter : List.of("client_id", "redirect_uri", "scope", "response_type", "request")) {
      Assertions.assertFalse(result.parameters().containsKey(parameter), parameter + " must not be in the URL");
    }
  }

  @Test
  void scopeLinesAreSentEachToItsLocation() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), true, true);
    model.getScope().setValue("openid");
    model.setRequestBodyScope("openid https://id.oidc.se/scope/naturalPersonInfo");

    final Result result = generate(model);

    Assertions.assertEquals("openid", result.url("scope"));
    Assertions.assertEquals("openid https://id.oidc.se/scope/naturalPersonInfo", result.claims().getClaim("scope"));
  }

  @Test
  void requestBodyScopeLineIsNotSentWhenItsBoxIsUnchecked() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), true, false);
    model.setRequestBodyScope("openid https://id.oidc.se/scope/naturalPersonInfo");
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertEquals("openid", result.url("scope"));
    Assertions.assertNull(result.claims().getClaim("scope"));
  }

  @Test
  void singleScopeValueIsUsedForBothLines() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), true, true);
    model.getScope().setValue("openid https://id.oidc.se/scope/sign");
    model.setRequestBodyScope(null);

    final Result result = generate(model);

    Assertions.assertEquals("openid https://id.oidc.se/scope/sign", result.url("scope"));
    Assertions.assertEquals("openid https://id.oidc.se/scope/sign", result.claims().getClaim("scope"));
  }

  @Test
  void urlScopeIsSentAsGivenWithoutOpenid() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    model.getScope().setValue("https://id.oidc.se/scope/naturalPersonInfo");

    final Result result = generate(model);

    Assertions.assertEquals("https://id.oidc.se/scope/naturalPersonInfo", result.url("scope"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "", "  " })
  void blankScopeLineIsNotSent(final String value) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), true, true);
    model.getScope().setValue(value);
    model.setRequestBodyScope(value);
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("scope"));
    Assertions.assertNull(result.claims().getClaim("scope"));
  }

  @Test
  void openidIsNotAddedToUrlWhenScopeIsOnlyInRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), false, true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("scope"));
    Assertions.assertEquals("openid", result.claims().getClaim("scope"));
  }

  // Different values in the request URL and in the request object (OpenID Connect Core 1.0, sections 6.1 and 6.3)

  @ParameterizedTest(name = "{0}")
  @MethodSource("splitRows")
  void eachLocationGetsItsOwnValue(final String row, final String urlValue, final String bodyValue)
      throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, urlValue, bodyValue, true);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    Assertions.assertEquals(urlValue, result.url(row));
    Assertions.assertEquals(bodyValue, result.claims().getClaim(row));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("splitRows")
  void theRequestObjectValueIsNotSentWhenTheSettingIsOff(final String row, final String urlValue,
      final String bodyValue) throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, urlValue, bodyValue, false);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    Assertions.assertEquals(urlValue, result.url(row));
    Assertions.assertEquals(urlValue, result.claims().getClaim(row));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("splitRows")
  void anOlderExportSendsOneValue(final String row, final String urlValue, final String bodyValue) throws Exception {
    // A request exported before the setting existed holds no setting at all
    final OIDCAuthnRequestParameterModel model = splitModel(row, urlValue, bodyValue, true);
    model.getAdvanced().setAllowDifferentValues(null);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    Assertions.assertEquals(urlValue, result.url(row));
    Assertions.assertEquals(urlValue, result.claims().getClaim(row));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("splitRows")
  void theRequestObjectValueIsNotSentWhenTheRowIsInOneLocationOnly(final String row, final String urlValue,
      final String bodyValue) throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, urlValue, bodyValue, true);
    place(splitParameter(model, row), false, true);

    final Result result = generate(model);

    Assertions.assertNull(result.url(row));
    Assertions.assertEquals(urlValue, result.claims().getClaim(row), "The row has one line, and it is sent");
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("splitRows")
  void aRowInTheUrlOnlyIsNotPutInTheRequestObject(final String row, final String urlValue, final String bodyValue)
      throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, urlValue, bodyValue, true);
    place(splitParameter(model, row), true, false);
    // Something else must be in the request object for it to be created
    model.getAdvanced().getLoginHint().setValue("hint");
    place(model.getAdvanced().getLoginHint(), false, true);

    final Result result = generate(model);

    Assertions.assertEquals(urlValue, result.url(row));
    Assertions.assertNull(result.claims().getClaim(row));
  }

  @ParameterizedTest
  @ValueSource(strings = { "state", "nonce" })
  void aGeneratedValueIsTheSameInBothLocations(final String row) throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, "", "", true);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    final String value = result.url(row);
    Assertions.assertNotNull(value);
    Assertions.assertFalse(value.isBlank());
    Assertions.assertEquals(value, result.claims().getClaim(row));
  }

  @ParameterizedTest
  @ValueSource(strings = { "state", "nonce" })
  void aValueTypedInTheUrlLineLeavesTheGeneratedValueInTheRequestObject(final String row) throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, "typed", "", true);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    Assertions.assertEquals("typed", result.url(row));
    final String generated = (String) result.claims().getClaim(row);
    Assertions.assertNotNull(generated);
    Assertions.assertNotEquals("typed", generated);
  }

  @ParameterizedTest
  @ValueSource(strings = { "state", "nonce" })
  void aValueTypedInTheRequestObjectLineLeavesTheGeneratedValueInTheUrl(final String row) throws Exception {
    final OIDCAuthnRequestParameterModel model = splitModel(row, "", "typed", true);
    place(splitParameter(model, row), true, true);

    final Result result = generate(model);

    Assertions.assertEquals("typed", result.claims().getClaim(row));
    final String generated = result.url(row);
    Assertions.assertNotNull(generated);
    Assertions.assertNotEquals("typed", generated);
  }

  @Test
  void differingClientIdAndResponseTypeAreSentAsBuilt() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().setAllowDifferentValues(true);
    model.getClientId().setRequestBodyValue(OTHER_CLIENT);
    place(model.getClientId(), true, true);
    model.getAdvanced().getResponseType().setRequestBodyValue("id_token");
    place(model.getAdvanced().getResponseType(), true, true);

    final Result result = generate(model);

    Assertions.assertEquals(RP, result.url("client_id"));
    Assertions.assertEquals("code", result.url("response_type"));
    Assertions.assertEquals(OTHER_CLIENT, result.claims().getClaim("client_id"));
    Assertions.assertEquals("id_token", result.claims().getClaim("response_type"));
  }

  @Test
  void theSettingDoesNotAffectRowsWithoutASecondLine() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().setAllowDifferentValues(true);
    // A value that only the covered rows have - the redirect URI keeps one value
    model.getRedirectUri().setRequestBodyValue("https://rp.example.com/other");
    place(model.getRedirectUri(), true, true);

    final Result result = generate(model);

    Assertions.assertEquals(REDIRECT_URI, result.url("redirect_uri"));
    Assertions.assertEquals(REDIRECT_URI, result.claims().getClaim("redirect_uri"));
  }

  // The claims row and its two boxes

  @ParameterizedTest(name = "inRequest={0}, inRequestBody={1}")
  @CsvSource({ "true,true", "true,false", "false,true", "false,false" })
  void claimsFollowTheirTwoBoxes(final boolean inRequest, final boolean inRequestBody) throws Exception {
    final OIDCAuthnRequestParameterModel model = claimsModel();
    model.setClaimInRequest(inRequest);
    model.setClaimInRequestBody(inRequestBody);

    final Result result = generate(model);

    Assertions.assertEquals(inRequest, result.url("claims") != null, "In the URL");
    Assertions.assertEquals(inRequestBody, result.claims().getClaim("claims") != null, "In the request object");
  }

  @Test
  void claimsInBothLocationsAreTheSame() throws Exception {
    final OIDCAuthnRequestParameterModel model = claimsModel();
    model.setClaimInRequest(true);
    model.setClaimInRequestBody(true);

    final Result result = generate(model);

    final JsonNode url = MAPPER.readTree(result.url("claims"));
    Assertions.assertEquals(url, MAPPER.valueToTree(result.claims().getClaim("claims")));
    Assertions.assertTrue(url.path("id_token").path("birthdate").path("essential").asBoolean());
  }

  @ParameterizedTest
  @ValueSource(booleans = { true, false })
  void claimsOfATemplateOrAnOlderExportKeepTheirPlacement(final boolean inRequestBody) throws Exception {
    // Templates and older exports only say whether the claims go in the request object
    final OIDCAuthnRequestParameterModel model = claimsModel();
    model.setClaimInRequest(null);
    model.setClaimInRequestBody(inRequestBody);

    final Result result = generate(model);

    Assertions.assertEquals(!inRequestBody, result.url("claims") != null, "In the URL");
    Assertions.assertEquals(inRequestBody, result.claims().getClaim("claims") != null, "In the request object");
  }

  /**
   * A model with claims, and a request object that is created whether the claims are placed in it or not.
   */
  private static OIDCAuthnRequestParameterModel claimsModel() {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.setClaims(Map.of("id_token", Map.of("birthdate", Map.of("essential", true))));
    model.getAdvanced().getState().setRequestBody(true);
    return model;
  }

  @Test
  void maxAgeIsNotSentByDefault() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    Assertions.assertEquals("0", model.getAdvanced().getMaxAge().getValue(), "The row is pre-filled with 0");

    final Result result = generate(model);

    Assertions.assertNull(result.url("max_age"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "0", "1", "300", "2147483647" })
  void maxAgeIsSentInUrl(final String value) throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    model.getAdvanced().getMaxAge().setValue(value);
    placeRow(model, "max_age", true, false);

    final Result result = generate(model);

    Assertions.assertEquals(value, result.url("max_age"));
    Assertions.assertNull(result.claims(), "No request object expected");
  }

  @Test
  void maxAgeIsSentAsANumberInRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().getMaxAge().setValue("300");
    placeRow(model, "max_age", false, true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("max_age"));
    Assertions.assertEquals(300L, requestObjectClaims(result).getClaim("max_age"));
    Assertions.assertTrue(requestObjectClaims(result).toString().contains("\"max_age\":300"),
        "max_age must be a JSON number, not a string");
  }

  @Test
  void maxAgeIsSentInBothLocations() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().getMaxAge().setValue("60");
    placeRow(model, "max_age", true, true);

    final Result result = generate(model);

    Assertions.assertEquals("60", result.url("max_age"));
    Assertions.assertEquals(60, result.claims().getClaim("max_age"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "", "   ", "-1", "1.5", "abc", "1e3", "+1", "99999999999999999999" })
  void maxAgeThatIsNotAWholeNumberIsNotSent(final String value) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().getMaxAge().setValue(value);
    placeRow(model, "max_age", true, true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("max_age"));
    Assertions.assertNull(result.claims(), "The request object holds nothing but the issuer and audience");
    Assertions.assertEquals(RP, result.url("client_id"), "The rest of the request is sent as normal");
  }

  @Test
  void maxAgeIsTrimmedAndLeadingZeroesAreKept() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    model.getAdvanced().getMaxAge().setValue("  007  ");
    placeRow(model, "max_age", true, false);

    final Result result = generate(model);

    Assertions.assertEquals("7", result.url("max_age"));
  }

  @Test
  void requestBodyModeMovesMaxAgeToTheRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    // The "In Request Body-mode" button moves an enabled row to the request object
    placeRow(model, "max_age", false, true);

    final Result result = generate(model);

    Assertions.assertNull(result.url("max_age"));
    Assertions.assertEquals(0, result.claims().getClaim("max_age"));
  }

  @Test
  void requestBodyModeLeavesOnlyRequiredParametersAndRequestObjectInUrl() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    // What the "In Request Body-mode" button does to the enabled rows of a new request
    for (final String row : List.of("redirect_uri", "prompt")) {
      placeRow(model, row, false, true);
    }
    for (final String row : List.of("client_id", "response_type", "scope")) {
      placeRow(model, row, true, true);
    }
    for (final String row : List.of("state", "nonce", "codeChallenge", "codeChallengeMethod")) {
      place(advanced(model, row), false, true);
    }
    model.getRequestObject().setModuleEnabled(true);

    final Result result = generate(model);

    Assertions.assertEquals(Set.of("client_id", "response_type", "scope", "request"),
        result.parameters().keySet());
    Assertions.assertEquals(challengeOf(result.verifier()), result.claims().getClaim("code_challenge"));
  }

  @Test
  void signRequestOnlyInRequestObjectWithSignApprovalScopeAndDefaults() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    place(model.getScope(), true, true);
    model.getScope().setValue("openid " + SCOPE_SIGN_APPROVAL);
    model.setRequestBodyScope("openid " + SCOPE_SIGN_APPROVAL);
    final SignatureParameterModel sig = model.getSignMessage();
    placeRow(model, SIGN_REQUEST, false, true);
    // What the UI does with the "TBS Data" box when the area is expanded with this scope
    sig.setIncludeTbsData(false);
    sig.setTbsData("Data to sign");
    sig.getSignMessage().setMessageSwedish("Meddelande");
    sig.getSignMessage().setMessageEnglish("Message");

    final Result result = generate(model);

    Assertions.assertFalse(result.parameters().containsKey(SIGN_REQUEST));
    final Map<String, Object> signRequest = map(requestObjectClaims(result).getClaim(SIGN_REQUEST));
    Assertions.assertEquals(Set.of("sign_message"), signRequest.keySet());
    Assertions.assertEquals(Map.of(
        "message#sv", b64("Meddelande"),
        "message#en", b64("Message"),
        "mime_type", "text/plain"), signRequest.get("sign_message"));
  }

  @Test
  void extensionsAreJsonObjectsInSerializedRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, USER_MESSAGE, false, true);
    placeRow(model, SIGN_REQUEST, false, true);

    final Result result = generate(model);

    final String payload = JWTParser.parse(result.url("request")).getParsedParts()[1].decodeToString();
    final Map<String, Object> json = JSONObjectUtils.parse(payload);
    Assertions.assertInstanceOf(Map.class, json.get(USER_MESSAGE));
    Assertions.assertInstanceOf(Map.class, json.get(SIGN_REQUEST));
  }

  static Stream<Arguments> mimeTypes() {
    return Stream.of(USER_MESSAGE, SIGN_REQUEST)
        .flatMap(extension -> Stream.of(true, false)
            .flatMap(inUrl -> Stream.of(null, "", "text/plain", "text/markdown", "text/dummy")
                .map(mimeType -> Arguments.of(extension, inUrl, mimeType))));
  }

  @ParameterizedTest(name = "{0}: inUrl={1}, mimeType={2}")
  @MethodSource("mimeTypes")
  void mimeTypeIsSentUnlessNotIncluded(final String extension, final boolean inUrl, final String mimeType)
      throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, extension, inUrl, !inUrl);
    messages(model, extension).setMimeType(mimeType);
    model.getAdvanced().getState().setRequestBody(true);

    final Map<String, Object> message = message(extension, generate(model), inUrl);

    if (mimeType == null || mimeType.isEmpty()) {
      Assertions.assertFalse(message.containsKey("mime_type"), "mime_type must not be sent: " + message);
    }
    else {
      Assertions.assertEquals(mimeType, message.get("mime_type"));
    }
  }

  static Stream<Arguments> extensionPlacements() {
    return Stream.of(USER_MESSAGE, SIGN_REQUEST)
        .flatMap(extension -> Stream.of(Arguments.of(extension, true), Arguments.of(extension, false)));
  }

  @ParameterizedTest(name = "{0}: inUrl={1}")
  @MethodSource("extensionPlacements")
  void allLanguageVariantsAreWritten(final String extension, final boolean inUrl) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, extension, inUrl, !inUrl);
    final OidcMessageParameterModel messages = messages(model, extension);
    messages.setMessageSwedish("sv");
    messages.setMessageEnglish("en");
    messages.setMessageGerman("de");
    messages.setMessageFrench("fr");
    messages.setMessageItalian("Messaggio");
    messages.setMessageSpanish("es");
    messages.setMessageDummy("xx");
    messages.setMessage("none");
    model.getAdvanced().getState().setRequestBody(true);

    final Map<String, Object> message = message(extension, generate(model), inUrl);

    Assertions.assertEquals(b64("Messaggio"), message.get("message#it"));
    Assertions.assertEquals(Set.of("message#sv", "message#en", "message#de", "message#fr", "message#it", "message#es",
        "message#xx", "message", "mime_type"), message.keySet());
  }

  @ParameterizedTest(name = "{0}: inUrl={1}")
  @MethodSource("extensionPlacements")
  void messagesAreSentAsEnteredWhenNotBase64Encoded(final String extension, final boolean inUrl) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, extension, inUrl, !inUrl);
    if (USER_MESSAGE.equals(extension)) {
      model.getUserMessage().setB64Encode(false);
    }
    else {
      model.getSignMessage().setB64Encode(false);
      model.getSignMessage().setTbsData("Data");
    }
    messages(model, extension).setMessageSwedish("Meddelande");
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    Assertions.assertEquals("Meddelande", message(extension, result, inUrl).get("message#sv"));
    if (SIGN_REQUEST.equals(extension)) {
      Assertions.assertEquals("Data", signRequest(result, inUrl).get("tbs_data"));
    }
  }

  @Test
  void userMessageInUrlIsJsonWithoutUiSettings() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    placeRow(model, USER_MESSAGE, true, false);

    final Result result = generate(model);

    Assertions.assertEquals(Map.of("message#sv", b64("msg"), "mime_type", "text/plain"),
        JSONObjectUtils.parse(result.url(USER_MESSAGE)));
  }

  @Test
  void signRequestInBothPlacesIsEncodedOnceInEach() throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, SIGN_REQUEST, true, true);
    model.getSignMessage().setTbsData("Data to sign");
    model.getSignMessage().getSignMessage().setMessageSwedish("Meddelande");

    final Result result = generate(model);

    for (final boolean inUrl : List.of(true, false)) {
      final Map<String, Object> signRequest = signRequest(result, inUrl);
      Assertions.assertEquals(Set.of("tbs_data", "sign_message"), signRequest.keySet(), "inUrl=" + inUrl);
      Assertions.assertEquals("Data to sign", unb64(signRequest.get("tbs_data")), "inUrl=" + inUrl);
      Assertions.assertEquals("Meddelande", unb64(map(signRequest.get("sign_message")).get("message#sv")));
    }
    Assertions.assertEquals("Data to sign", model.getSignMessage().getTbsData(), "The model must not be changed");
  }

  static Stream<Arguments> tbsDataSettings() {
    return Stream.of(
        Arguments.of(true, "Data", true),
        Arguments.of(null, "Data", true),
        Arguments.of(false, "Data", false),
        Arguments.of(true, null, false),
        Arguments.of(true, "", true));
  }

  @ParameterizedTest(name = "includeTbsData={0}, tbsData={1}")
  @MethodSource("tbsDataSettings")
  void tbsDataIsSentWhenIncluded(final Boolean include, final String tbsData, final boolean expected)
      throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    placeRow(model, SIGN_REQUEST, true, true);
    model.getSignMessage().setIncludeTbsData(include);
    model.getSignMessage().setTbsData(tbsData);

    final Result result = generate(model);

    Assertions.assertEquals(expected, signRequest(result, true).containsKey("tbs_data"), "In URL");
    Assertions.assertEquals(expected, signRequest(result, false).containsKey("tbs_data"), "In request object");
  }

  @ParameterizedTest
  @ValueSource(strings = { "key", "other" })
  void signRequestInUrlIsJwtSignedWithSelectedKey(final String kid) throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    placeRow(model, SIGN_REQUEST, true, false);
    model.getSignMessage().setTbsData("Data");
    model.getSignMessage().setSignKey(kid);
    // The request object signing key does not apply
    model.getKeys().setSignKey("key");

    final Result result = generate(model);

    final SignedJWT jwt = SignedJWT.parse(result.url(SIGN_REQUEST));
    Assertions.assertEquals(kid, jwt.getHeader().getKeyID());
    Assertions.assertTrue(jwt.verify(verifier(keys.get(kid))), "Signature must verify with the selected key");
    final JWK unrelatedKey = keys.get(kid) instanceof ECKey
        ? new ECKeyGenerator(Curve.P_256).generate()
        : new RSAKeyGenerator(2048).generate();
    Assertions.assertFalse(jwt.verify(verifier(unrelatedKey)));
    Assertions.assertEquals(Set.of("tbs_data", "sign_message"), jwt.getJWTClaimsSet().getClaims().keySet(),
        "The claims set is the sign request object only");
  }

  @Test
  void signRequestInUrlIsSignedWithRegisteredKeyAndNotEncryptedByDefault() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    placeRow(model, SIGN_REQUEST, true, false);

    final JWT jwt = JWTParser.parse(generate(model).url(SIGN_REQUEST));

    final SignedJWT signed = Assertions.assertInstanceOf(SignedJWT.class, jwt);
    Assertions.assertEquals(key.getKeyID(), signed.getHeader().getKeyID());
    Assertions.assertTrue(signed.verify(verifier(key)));
  }

  @Test
  void unsignedSignRequestInUrlIsUnsecuredJwt() throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    placeRow(model, SIGN_REQUEST, true, false);
    model.getSignMessage().setSignJwt(false);
    model.getSignMessage().setSignKey(null);

    final JWT jwt = JWTParser.parse(generate(model).url(SIGN_REQUEST));

    Assertions.assertInstanceOf(PlainJWT.class, jwt);
    Assertions.assertEquals(Algorithm.NONE, jwt.getHeader().getAlgorithm());
  }

  @ParameterizedTest
  @ValueSource(booleans = { true, false })
  void encryptedSignRequestInUrlIsNestedJwt(final boolean signed) throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    placeRow(model, SIGN_REQUEST, true, false);
    model.getSignMessage().setTbsData("Data");
    model.getSignMessage().setSignJwt(signed);
    model.getSignMessage().setSignKey("other");
    model.getSignMessage().setEncryptJwt(true);

    final JWT inner = decryptNested(generate(model).url(SIGN_REQUEST));

    if (signed) {
      final SignedJWT signedJwt = Assertions.assertInstanceOf(SignedJWT.class, inner);
      Assertions.assertTrue(signedJwt.verify(verifier(otherKey)));
    }
    else {
      Assertions.assertInstanceOf(PlainJWT.class, inner);
    }
    Assertions.assertEquals(b64("Data"), inner.getJWTClaimsSet().getClaim("tbs_data"));
  }

  @ParameterizedTest
  @ValueSource(booleans = { true, false })
  void encryptedRequestObjectIsNestedJwt(final boolean signed) throws Exception {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getRequestObject().setSignRequest(signed);
    model.getRequestObject().setEncryptRequest(true);
    model.getAdvanced().getState().setRequestBody(true);

    final Result result = generate(model);

    final JWT inner = decryptNested(result.url("request"));
    if (signed) {
      Assertions.assertTrue(Assertions.assertInstanceOf(SignedJWT.class, inner).verify(verifier(key)));
    }
    else {
      Assertions.assertInstanceOf(PlainJWT.class, inner);
    }
    Assertions.assertEquals(result.claims().toJSONObject(), inner.getJWTClaimsSet().toJSONObject());
    Assertions.assertNull(inner.getJWTClaimsSet().getClaim("payload"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "request", SIGN_REQUEST })
  void encryptionFailsTheSameWayWithoutUsableEncryptionKey(final String jwt) {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getKeys().setEncKey(null);
    if ("request".equals(jwt)) {
      model.getRequestObject().setEncryptRequest(true);
      model.getAdvanced().getState().setRequestBody(true);
    }
    else {
      placeRow(model, SIGN_REQUEST, true, false);
      model.getSignMessage().setEncryptJwt(true);
    }

    final RuntimeException e = Assertions.assertThrows(RuntimeException.class, () -> generate(model));
    Assertions.assertEquals("Failed to determine key for kid null", e.getMessage());
  }

  @ParameterizedTest
  @MethodSource("templateNames")
  void templatesGenerateRequests(final String name) throws Exception {
    final OIDCAuthnRequestParameterModel model = applyTemplate(defaultModel(), template(name));

    final Result result = generate(model);

    Assertions.assertFalse(result.parameters().isEmpty());
  }

  @Test
  void signHiddenTemplateSendsSignRequestInEncryptedRequestObject() throws Exception {
    final OIDCAuthnRequestParameterModel model = applyTemplate(defaultModel(), template("Sign Hidden"));

    final Result result = generate(model);

    final Map<String, Object> signRequest = map(decryptNested(result.url("request")).getJWTClaimsSet()
        .getClaim(SIGN_REQUEST));
    Assertions.assertEquals("Sign message", unb64(signRequest.get("tbs_data")));
    Assertions.assertEquals(Map.of(
        "message#sv", b64("Sign: Meddelande"),
        "message#en", b64("Sign: Message"),
        "mime_type", "text/plain"), signRequest.get("sign_message"));
  }

  static Stream<String> templateNames() throws Exception {
    return templates().stream().map(t -> t.get("name").asString());
  }

  private static OidcMessageParameterModel messages(final OIDCAuthnRequestParameterModel model,
      final String extension) {
    return USER_MESSAGE.equals(extension) ? model.getUserMessage() : model.getSignMessage().getSignMessage();
  }

  /**
   * Gets the message object of an extension, i.e., the user message or the sign message of the sign request.
   */
  private static Map<String, Object> message(final String extension, final Result result, final boolean inUrl)
      throws Exception {
    if (SIGN_REQUEST.equals(extension)) {
      return map(signRequest(result, inUrl).get("sign_message"));
    }
    return inUrl
        ? JSONObjectUtils.parse(result.url(USER_MESSAGE))
        : map(requestObjectClaims(result).getClaim(USER_MESSAGE));
  }

  /**
   * Gets the sign request from the URL, where it is a signed or unsecured JWT, or from the request object.
   */
  private static Map<String, Object> signRequest(final Result result, final boolean inUrl) throws Exception {
    return inUrl
        ? JWTParser.parse(result.url(SIGN_REQUEST)).getJWTClaimsSet().getClaims()
        : map(requestObjectClaims(result).getClaim(SIGN_REQUEST));
  }

  /**
   * Gets the claims of the request object as sent, i.e., parsed from the {@code request} parameter.
   */
  private static JWTClaimsSet requestObjectClaims(final Result result) throws Exception {
    return JWTParser.parse(result.url("request")).getJWTClaimsSet();
  }

  /**
   * Decrypts an encrypted JWT with the OP's key, and checks that it is a nested JWT.
   */
  private static JWT decryptNested(final String serialized) throws Exception {
    final EncryptedJWT encrypted = EncryptedJWT.parse(serialized);
    Assertions.assertEquals("JWT", encrypted.getHeader().getContentType());
    Assertions.assertEquals(encKey.getKeyID(), encrypted.getHeader().getKeyID());
    encrypted.decrypt(new RSADecrypter(encKey.toRSAKey()));
    return JWTParser.parse(encrypted.getPayload().toString());
  }

  private static JWSVerifier verifier(final JWK jwk) throws Exception {
    return jwk instanceof final ECKey ecKey ? new ECDSAVerifier(ecKey) : new RSASSAVerifier(jwk.toRSAKey());
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> map(final Object value) {
    return Assertions.assertInstanceOf(Map.class, value, "Expected a JSON object");
  }

  private static String b64(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static String unb64(final Object value) {
    return new String(Base64.getDecoder().decode((String) value), StandardCharsets.UTF_8);
  }

  static Stream<Arguments> sendMethodScenarios() {
    return Stream.of(
        Arguments.of("default request", (ModelSetup) model -> {
        }),
        Arguments.of("request object, signed and encrypted", (ModelSetup) model -> {
          for (final String row : List.of("redirect_uri", "prompt", "acr_values")) {
            placeRow(model, row, false, true);
          }
          model.getRequestObject().setModuleEnabled(true);
          model.getRequestObject().setSignRequest(true);
          model.getRequestObject().setEncryptRequest(true);
        }),
        Arguments.of("extensions and values needing encoding", (ModelSetup) model -> {
          placeRow(model, USER_MESSAGE, true, false);
          placeRow(model, SIGN_REQUEST, true, false);
          model.getUserMessage().setB64Encode(false);
          model.getUserMessage().setMessageSwedish("Räksmörgås & a=b+c ? / % \"x\" <y>");
          model.getAdvanced().getLoginHint().setValue("user name+tag@example.com&x=1");
          model.getAdvanced().getLoginHint().setValuePresent(true);
          model.setClaims(Map.of("id_token", Map.of("https://id.oidc.se/claim/personalIdentityNumber",
              Map.of("essential", true))));
          model.setClaimInRequest(true);
        }),
        Arguments.of("no parameters", (ModelSetup) model -> {
          for (final String row : List.of("client_id", "redirect_uri", "scope", "response_type", "prompt")) {
            placeRow(model, row, false, false);
          }
          for (final String row : List.of("state", "nonce", "codeChallenge", "codeChallengeMethod")) {
            place(advanced(model, row), false, false);
          }
        }));
  }

  @FunctionalInterface
  private interface ModelSetup {
    void apply(OIDCAuthnRequestParameterModel model);
  }

  @ParameterizedTest(name = "{0}, endpoint={2}")
  @MethodSource("sendMethodCases")
  void postSendsExactlyTheParametersOfTheGetQueryString(
      final String scenario, final ModelSetup setup, final String endpoint) throws Exception {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    setup.apply(model);

    final Result result = generate(model, new HashMap<>(), endpoint);

    Assertions.assertEquals(SentAuthorizationRequest.Method.GET, result.get().method());
    Assertions.assertNull(result.get().parameters());
    Assertions.assertEquals(SentAuthorizationRequest.Method.POST, result.post().method());
    Assertions.assertEquals(endpoint, result.post().url(), "Nothing but the endpoint must be in the POST URL");

    final Map<String, List<String>> getQuery = queryOf(result.get().url());
    final Map<String, List<String>> postParameters = new LinkedHashMap<>(queryOf(result.post().url()));
    Assertions.assertTrue(postParameters.keySet().stream().noneMatch(result.post().parameters()::containsKey),
        "A form parameter must not repeat a parameter of the endpoint's own query string");
    postParameters.putAll(result.post().parameters());
    Assertions.assertEquals(getQuery, postParameters);
    Assertions.assertEquals(result.parameters(), queryOf(result.get().url()), "GET is sent as the request URL");
  }

  static Stream<Arguments> sendMethodCases() {
    return sendMethodScenarios().flatMap(scenario -> Stream.of(AUTHORIZATION_ENDPOINT,
            "https://op.example.com/authorize?tenant=a%26b&mode=test")
        .map(endpoint -> Arguments.of(scenario.get()[0], scenario.get()[1], endpoint)));
  }

  @Test
  void getUrlWithoutParametersIsTheEndpointAsConfigured() throws Exception {
    final String endpoint = "https://op.example.com/authorize?tenant=a";
    final OIDCAuthnRequestParameterModel model = defaultModel();
    sendMethodScenarios().filter(a -> "no parameters".equals(a.get()[0])).findFirst()
        .map(a -> (ModelSetup) a.get()[1]).orElseThrow().apply(model);

    final Result result = generate(model, new HashMap<>(), endpoint);

    Assertions.assertEquals(Map.of(), result.post().parameters());
    Assertions.assertEquals(endpoint, result.get().url());
  }

  private static Map<String, List<String>> queryOf(final String url) {
    return URLUtils.parseParameters(URI.create(url).getRawQuery());
  }

  /**
   * The outcome of generating a request.
   *
   * @param parameters the parameters of the URL that is sent
   * @param claims the claims of the request object, or {@code null} if there is no request object
   * @param verifier the code verifier saved for the token request, or {@code null}
   * @param session the attributes saved in the session
   * @param get the request as sent with GET
   * @param post the same request as sent with POST
   */
  private record Result(Map<String, List<String>> parameters, JWTClaimsSet claims, CodeVerifier verifier,
      Map<String, Object> session, SentAuthorizationRequest get, SentAuthorizationRequest post) {

    String url(final String name) {
      return Optional.ofNullable(this.parameters.get(name)).map(List::getFirst).orElse(null);
    }
  }

  private static Result generate(final OIDCAuthnRequestParameterModel model) throws Exception {
    return generate(model, new HashMap<>());
  }

  private static Result generate(final OIDCAuthnRequestParameterModel model, final Map<String, Object> session)
      throws Exception {
    return generate(model, session, AUTHORIZATION_ENDPOINT);
  }

  /**
   * Generates a request the way {@code OidcRestController.generateAuthnRequest} does. The request is taken as sent
   * both with GET and with POST.
   */
  @SuppressWarnings("unchecked")
  private static Result generate(final OIDCAuthnRequestParameterModel model, final Map<String, Object> session,
      final String endpoint) throws Exception {
    session.remove("jwt_claims");
    final AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
        new ResponseType("code"), new Scope("openid"), new ClientID(model.getClientId().getValue()),
        URI.create(model.getRedirectUri().getValue()))
        .endpointURI(URI.create(endpoint));
    // As OidcRestController, which fails for a key ID that does not name a key
    final Function<String, JWK> kidToJwk = kid -> Optional.ofNullable(kid).map(keys::get)
        .orElseThrow(() -> new RuntimeException("Failed to determine key for kid %s".formatted(kid)));
    final AuthorizationParameterResolver resolver = new AuthorizationParameterResolver(model, false, session::put);
    final AuthenticationRequest request = AuthorizationRequestCustomizer.customize(builder, kidToJwk, resolver).build();

    final URI uri = AuthorizationRequestCustomizer.toURI(request, resolver);
    if (AUTHORIZATION_ENDPOINT.equals(endpoint)
        && !AuthorizationRequestCustomizer.toParameters(request, resolver).isEmpty()) {
      Assertions.assertTrue(uri.toString().startsWith(AUTHORIZATION_ENDPOINT + "?"), uri.toString());
    }
    final SentAuthorizationRequest get =
        AuthorizationRequestCustomizer.toSentRequest(request, resolver, SentAuthorizationRequest.Method.GET);
    final SentAuthorizationRequest post =
        AuthorizationRequestCustomizer.toSentRequest(request, resolver, SentAuthorizationRequest.Method.POST);
    final Pair<CodeChallengeMethod, CodeVerifier> verifier =
        (Pair<CodeChallengeMethod, CodeVerifier>) session.get(AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE);
    return new Result(URLUtils.parseParameters(uri.getRawQuery()), (JWTClaimsSet) session.get("jwt_claims"),
        verifier != null ? verifier.getRight() : null, session, get, post);
  }

  private static String challengeOf(final CodeVerifier verifier) {
    Assertions.assertNotNull(verifier, "Expected a saved code verifier");
    return CodeChallenge.compute(CodeChallengeMethod.S256, verifier).getValue();
  }

  /**
   * The model as handed to the UI by {@code /oidc/authn/template}, without the key lists.
   */
  private static OIDCAuthnRequestParameterModel defaultModel() {
    return OIDCAuthnRequestParameterModel.builder()
        .requestBodyScope("openid")
        .requestMode("request")
        .op("https://op.example.com")
        .rp(RP)
        .signMessage(OidcRestController.createDefaultSignRequest(key.getKeyID()))
        .userMessage(OidcRestController.createDefaultUserMessage())
        .scope(new ModelParameter("openid", false, true))
        .redirectUri(new ModelParameter(REDIRECT_URI, false, true))
        .clientId(new ModelParameter(RP, false, true))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequest(false)
        .claimInRequestBody(false)
        .advanced(OidcRestController.createDefaultAdvancedOptions())
        .keys(KeyOptionsParameterModel.builder()
            .signKey(key.getKeyID())
            .encKey(encKey.getKeyID())
            .moduleEnabled(true)
            .build())
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter(RP, true, true))
            .audience(new ModelParameter(OP_ISSUER, true, true))
            .signRequest(false)
            .encryptRequest(false)
            .moduleEnabled(false)
            .build())
        .build();
  }

  /**
   * A model with request object options enabled. Note that a request object is only created when it holds more than
   * the issuer and audience.
   */
  private static OIDCAuthnRequestParameterModel requestObjectModel() {
    final OIDCAuthnRequestParameterModel model = defaultModel();
    model.getRequestObject().setModuleEnabled(true);
    return model;
  }

  /**
   * The rows that may send one value in the request URL and another in the request object, with a value for each
   * location. The row name is also the name of the parameter as it is sent.
   */
  static Stream<Arguments> splitRows() {
    return Stream.of(
        Arguments.of("state", "url-state", "body-state"),
        Arguments.of("nonce", "url-nonce", "body-nonce"),
        Arguments.of("prompt", "login", "consent select_account"),
        Arguments.of("acr_values", LOA3, LOA2),
        Arguments.of("client_id", RP, OTHER_CLIENT),
        Arguments.of("response_type", "code", "id_token"));
  }

  private static ModelParameter splitParameter(final OIDCAuthnRequestParameterModel model, final String row) {
    return switch (row) {
      case "state" -> model.getAdvanced().getState();
      case "nonce" -> model.getAdvanced().getNonce();
      case "prompt" -> model.getAdvanced().getPrompt();
      case "acr_values" -> model.getAcrValues();
      case "client_id" -> model.getClientId();
      case "response_type" -> model.getAdvanced().getResponseType();
      default -> throw new IllegalArgumentException(row);
    };
  }

  /**
   * A model with request object options enabled, and one row sending a value of its own in the request object.
   */
  private static OIDCAuthnRequestParameterModel splitModel(final String row, final String urlValue,
      final String bodyValue, final boolean allowed) {
    final OIDCAuthnRequestParameterModel model = requestObjectModel();
    model.getAdvanced().setAllowDifferentValues(allowed);
    final ModelParameter parameter = splitParameter(model, row);
    parameter.setValue(urlValue);
    parameter.setRequestBodyValue(bodyValue);
    return model;
  }

  private static ModelParameter advanced(final OIDCAuthnRequestParameterModel model, final String row) {
    return switch (row) {
      case "state" -> model.getAdvanced().getState();
      case "nonce" -> model.getAdvanced().getNonce();
      case "codeChallenge" -> model.getAdvanced().getCodeChallenge();
      case "codeChallengeMethod" -> model.getAdvanced().getCodeChallengeMethod();
      case "maxAge" -> model.getAdvanced().getMaxAge();
      default -> throw new IllegalArgumentException(row);
    };
  }

  /**
   * Sets the "In Request" and "In Request Body" boxes of a row identified by its parameter name.
   */
  private static void placeRow(final OIDCAuthnRequestParameterModel model, final String row,
      final boolean inRequest, final boolean inRequestBody) {
    final AdvancedOptionsParamterModel advanced = model.getAdvanced();
    switch (row) {
      case "client_id" -> place(model.getClientId(), inRequest, inRequestBody);
      case "redirect_uri" -> place(model.getRedirectUri(), inRequest, inRequestBody);
      case "scope" -> place(model.getScope(), inRequest, inRequestBody);
      case "response_type" -> place(advanced.getResponseType(), inRequest, inRequestBody);
      case "prompt" -> {
        advanced.getPrompt().setValue("login consent");
        place(advanced.getPrompt(), inRequest, inRequestBody);
      }
      case "acr_values" -> {
        model.getAcrValues().setValue("http://id.elegnamnden.se/loa/1.0/loa3");
        place(model.getAcrValues(), inRequest, inRequestBody);
      }
      case "login_hint" -> {
        advanced.getLoginHint().setValue("hint");
        place(advanced.getLoginHint(), inRequest, inRequestBody);
      }
      case "max_age" -> place(advanced.getMaxAge(), inRequest, inRequestBody);
      case USER_MESSAGE -> {
        model.getUserMessage().setValuePresent(inRequest);
        model.getUserMessage().setRequestBody(inRequestBody);
      }
      case SIGN_REQUEST -> {
        model.getSignMessage().setValuePresent(inRequest);
        model.getSignMessage().setRequestBody(inRequestBody);
      }
      default -> throw new IllegalArgumentException(row);
    }
  }

  private static void place(final ModelParameter parameter, final boolean inRequest, final boolean inRequestBody) {
    parameter.setValuePresent(inRequest);
    parameter.setRequestBody(inRequestBody);
  }

  private static List<JsonNode> templates() throws Exception {
    try (final InputStream in = AuthorizationParameterResolverTest.class.getResourceAsStream(
        "/static/templates/oidc-authn-templates.json")) {
      final List<JsonNode> templates = new ArrayList<>();
      MAPPER.readTree(in).forEach(templates::add);
      return templates;
    }
  }

  private static JsonNode template(final String name) throws Exception {
    return templates().stream()
        .filter(t -> name.equals(t.get("name").asString()))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("No template " + name));
  }

  /**
   * Applies a template the way {@code OIDCAuthnRequest.applyTemplate} in {@code oidc-authn.js} does.
   */
  private static OIDCAuthnRequestParameterModel applyTemplate(
      final OIDCAuthnRequestParameterModel model, final JsonNode template) {
    final ObjectNode pars = MAPPER.valueToTree(model);
    if (template.path("scope").has("value")) {
      pars.set("requestBodyScope", template.get("scope").get("value"));
    }
    for (final String field : List.of("clientId", "redirectUri", "scope", "acrValues", "keys")) {
      if (template.has(field)) {
        ((ObjectNode) pars.get(field)).setAll((ObjectNode) template.get(field));
      }
    }
    for (final String field : List.of("signMessage", "userMessage", "advanced", "requestObject")) {
      if (template.has(field)) {
        final ObjectNode target = (ObjectNode) pars.get(field);
        template.get(field).properties().forEach(e -> {
          if (e.getValue().isObject() && target.get(e.getKey()) instanceof final ObjectNode child) {
            child.setAll((ObjectNode) e.getValue());
          }
          else {
            target.set(e.getKey(), e.getValue());
          }
        });
      }
    }
    return MAPPER.treeToValue(pars, OIDCAuthnRequestParameterModel.class);
  }
}
