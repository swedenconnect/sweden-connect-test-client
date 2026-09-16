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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.JWTClaimsSet;
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
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * Tests for {@link AuthorizationParameterResolver} - where PKCE, state and nonce are placed in an authentication
 * request, and the outcome of the request templates.
 *
 * @author Martin Lindström
 */
class AuthorizationParameterResolverTest {

  private static final String RP = "https://rp.example.com";
  private static final String REDIRECT_URI = "https://rp.example.com/oidc/redirect/rp";
  private static final String AUTHORIZATION_ENDPOINT = "https://op.example.com/authorize";
  private static final String TOKEN_ENDPOINT = "https://op.example.com/token";

  private static final String USER_MESSAGE = "https://id.oidc.se/param/userMessage";
  private static final String SIGN_REQUEST = "https://id.oidc.se/param/signRequest";

  private static final JsonMapper MAPPER = JsonMapper.builder().build();

  private static JWK key;

  @BeforeAll
  static void generateKey() throws Exception {
    key = new RSAKeyGenerator(2048).keyID("key").generate();
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

    // max_age=0 is always added by the request generation and has no row
    Assertions.assertEquals(Set.of("client_id", "response_type", "scope", "request", "max_age"),
        result.parameters().keySet());
    Assertions.assertEquals(challengeOf(result.verifier()), result.claims().getClaim("code_challenge"));
  }

  /**
   * The outcome of generating a request.
   *
   * @param parameters the parameters of the URL that is sent
   * @param claims the claims of the request object, or {@code null} if there is no request object
   * @param verifier the code verifier saved for the token request, or {@code null}
   */
  private record Result(Map<String, List<String>> parameters, JWTClaimsSet claims, CodeVerifier verifier) {

    String url(final String name) {
      return Optional.ofNullable(this.parameters.get(name)).map(List::getFirst).orElse(null);
    }
  }

  private static Result generate(final OIDCAuthnRequestParameterModel model) throws Exception {
    return generate(model, new HashMap<>());
  }

  /**
   * Generates a request the way {@code OidcRestController.generateAuthnRequest} does.
   */
  @SuppressWarnings("unchecked")
  private static Result generate(final OIDCAuthnRequestParameterModel model, final Map<String, Object> session)
      throws Exception {
    session.remove("jwt_claims");
    final AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
        new ResponseType("code"), new Scope("openid"), new ClientID(model.getClientId().getValue()),
        URI.create(model.getRedirectUri().getValue()))
        .endpointURI(URI.create(AUTHORIZATION_ENDPOINT));
    builder.maxAge(0);
    final Function<String, JWK> kidToJwk = kid -> key;
    final AuthorizationParameterResolver resolver = new AuthorizationParameterResolver(model, false, session::put);
    final AuthenticationRequest request = AuthorizationRequestCustomizer.customize(builder, kidToJwk, resolver).build();

    final URI uri = AuthorizationRequestCustomizer.toURI(request, resolver);
    Assertions.assertTrue(uri.toString().startsWith(AUTHORIZATION_ENDPOINT + "?"), uri.toString());
    final Pair<CodeChallengeMethod, CodeVerifier> verifier =
        (Pair<CodeChallengeMethod, CodeVerifier>) session.get(AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE);
    return new Result(URLUtils.parseParameters(uri.getRawQuery()), (JWTClaimsSet) session.get("jwt_claims"),
        verifier != null ? verifier.getRight() : null);
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
        .signMessage(SignatureParameterModel.builder()
            .b64Encode(true)
            .signMessage(OidcMessageParameterModel.builder().build())
            .requestBody(false)
            .valuePresent(false)
            .build())
        .userMessage(OidcMessageParameterModel.builder()
            .b64Encode(true)
            .messageSwedish("msg")
            .valuePresent(false)
            .requestBody(false)
            .build())
        .scope(new ModelParameter("openid", false, true))
        .redirectUri(new ModelParameter(REDIRECT_URI, false, true))
        .clientId(new ModelParameter(RP, false, true))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequestBody(false)
        .advanced(OidcRestController.createDefaultAdvancedOptions())
        .keys(KeyOptionsParameterModel.builder()
            .signKey(key.getKeyID())
            .encKey(key.getKeyID())
            .moduleEnabled(true)
            .build())
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter(RP, true, true))
            .audience(new ModelParameter(TOKEN_ENDPOINT, true, true))
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

  private static ModelParameter advanced(final OIDCAuthnRequestParameterModel model, final String row) {
    return switch (row) {
      case "state" -> model.getAdvanced().getState();
      case "nonce" -> model.getAdvanced().getNonce();
      case "codeChallenge" -> model.getAdvanced().getCodeChallenge();
      case "codeChallengeMethod" -> model.getAdvanced().getCodeChallengeMethod();
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
      case "prompt" -> place(advanced.getPrompt(), inRequest, inRequestBody);
      case "acr_values" -> {
        model.getAcrValues().setValue("http://id.elegnamnden.se/loa/1.0/loa3");
        place(model.getAcrValues(), inRequest, inRequestBody);
      }
      case "login_hint" -> {
        advanced.getLoginHint().setValue("hint");
        place(advanced.getLoginHint(), inRequest, inRequestBody);
      }
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
