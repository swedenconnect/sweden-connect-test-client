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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.config.OidcProperties;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;

/**
 * Token exchange (RFC 8693) and calls to protected resources, from the authentication result.
 * <p>
 * "Send Token Exchange Request" exchanges a token - by default the access token of the authentication - at the token
 * endpoint of the OP selected for the authentication. The test client authenticates as the RP selected for the
 * authentication, so this is an RP (or a protected resource that holds the RP's keys) acting as a client in the
 * sense of the Ena OAuth 2.0 chaining profile. The request and response are checked with {@link TokenExchangeChecks}.
 * </p>
 * <p>
 * "Call Protected Resource" sends an access token to one of the protected resources configured under
 * {@code testclient.oidc.protected-resources}. URLs from the browser are never called.
 * </p>
 *
 * @author Simon Tardell
 */
@Slf4j
@RestController
@RequestMapping("/oidc")
public class TokenExchangeController {

  private static final ObjectMapper objectMapper = JsonMapper.builder().build();

  private final HttpSession httpSession;
  private final RestClient client;
  private final TokenRequestSender tokenRequestSender;
  private final List<OidcProperties.ProtectedResource> protectedResources;
  private final OIDCOPMetadataFetcher metadataFetcher;

  /**
   * Constructor.
   *
   * @param httpSession the HTTP session
   * @param client the HTTP client
   * @param oidcProperties the OIDC configuration (for the protected resources)
   * @param metadataFetcher reads the metadata of the OP (for the scopes it supports)
   */
  public TokenExchangeController(@Nonnull final HttpSession httpSession, @Nonnull final RestClient client,
      @Nonnull final OidcProperties oidcProperties, @Nonnull final OIDCOPMetadataFetcher metadataFetcher) {
    this.httpSession = httpSession;
    this.metadataFetcher = metadataFetcher;
    this.client = client;
    this.tokenRequestSender = new TokenRequestSender(client);
    this.protectedResources = List.copyOf(oidcProperties.getProtectedResources());
  }

  /**
   * Gets the defaults of the token exchange form for the latest authentication, including the values suggested for
   * {@code resource}, {@code audience} and {@code scope}: the resource identifiers of the configured protected
   * resources, and the {@code scopes_supported} of the OP.
   *
   * @return the defaults, or an object without a token endpoint if there is no OIDC authentication in the session
   */
  @GetMapping(value = "/authn/token-exchange/defaults", produces = MediaType.APPLICATION_JSON_VALUE)
  public TokenExchangeDefaults tokenExchangeDefaults() {
    final List<String> resources = this.protectedResources.stream()
        .map(OidcProperties.ProtectedResource::getResource)
        .filter(Objects::nonNull)
        .distinct()
        .toList();
    final OidcOp op = (OidcOp) this.httpSession.getAttribute("selected_op");
    final OidcRp rp = (OidcRp) this.httpSession.getAttribute("selected_rp");
    if (op == null || rp == null) {
      return new TokenExchangeDefaults(null, null, TokenRequestFactory.AUTH_METHODS, resources, List.of());
    }
    return new TokenExchangeDefaults(op.getTokenEndpoint(), rp.getEntityId(), TokenRequestFactory.AUTH_METHODS,
        resources, this.scopesSupported(op));
  }

  /**
   * Gets the {@code scopes_supported} of an OP.
   *
   * @param op the OP
   * @return the scopes, or an empty list if the metadata cannot be read or holds none
   */
  @Nonnull
  private List<String> scopesSupported(@Nonnull final OidcOp op) {
    try {
      final Object scopes = Optional.ofNullable(this.metadataFetcher.getOPMetadata(op))
          .map(m -> m.get("scopes_supported"))
          .orElse(null);
      if (scopes instanceof final Collection<?> c) {
        return c.stream().map(String::valueOf).toList();
      }
    }
    catch (final Exception e) {
      log.info("Could not read scopes_supported of {}: {}", op.getEntityId(), OidcController.message(e));
    }
    return List.of();
  }

  /**
   * Sends a token exchange request to the token endpoint of the OP selected for the authentication.
   *
   * @param model the request
   * @return the request as sent, the response and the checks
   */
  @PostMapping(value = "/authn/token-exchange", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public TokenExchangeResult sendTokenExchangeRequest(@Nonnull @RequestBody final TokenExchangeRequestModel model) {
    final OidcOp op = (OidcOp) this.httpSession.getAttribute("selected_op");
    final OidcRp rp = (OidcRp) this.httpSession.getAttribute("selected_rp");
    if (op == null || rp == null) {
      log.info("Token exchange request rejected: there is no OIDC authentication in the session");
      return TokenExchangeResult.builder()
          .error(TokenEndpointError.builder()
              .message("There is no OIDC authentication in the session - restart the authentication")
              .build())
          .build();
    }

    final String clientId = Optional.ofNullable(trim(model.getClientId())).orElse(rp.getEntityId());
    final String authMethod = Optional.ofNullable(trim(model.getAuthMethod()))
        .orElse(TokenRequestParameterModel.PRIVATE_KEY_JWT);

    // The client authentication is built the same way as for the token request of the authentication
    final TokenRequestParameterModel settings = TokenRequestParameterModel.builder()
        .authMethod(authMethod)
        .grantType(row(TokenExchangeChecks.GRANT_TYPE, true))
        .code(row("", false))
        .redirectUri(row("", false))
        .codeVerifier(row("", false))
        .clientId(row(clientId, !TokenRequestParameterModel.CLIENT_SECRET_BASIC.equals(authMethod)))
        .clientSecret(row(Optional.ofNullable(model.getClientSecret()).orElse(""),
            TokenRequestParameterModel.CLIENT_SECRET_POST.equals(authMethod)))
        .clientAssertionType(row(TokenRequestParameterModel.JWT_BEARER_ASSERTION_TYPE,
            isJwtAuth(authMethod)))
        .clientAssertion(row("", isJwtAuth(authMethod)))
        .assertionIss(row(clientId, true))
        .assertionSub(row(clientId, true))
        .assertionAud(row(op.getIssuer(), true))
        .assertionIat(row("", true))
        .assertionJti(row("", true))
        .assertionExp(row("", true))
        .build();

    final SentTokenRequest clientAuth;
    try {
      clientAuth = TokenRequestFactory.create(settings, op.getTokenEndpoint(), null, null,
          this.signingCredential(rp), Instant.now());
    }
    catch (final TokenRequestException e) {
      log.info("Token exchange request for '{}' not sent: {}", clientId, e.getMessage());
      return TokenExchangeResult.builder()
          .error(TokenEndpointError.builder()
              .message("The token exchange request was not sent to %s. %s.".formatted(op.getTokenEndpoint(),
                  e.getMessage()))
              .build())
          .build();
    }

    final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
    parameters.add("grant_type", TokenExchangeChecks.GRANT_TYPE);
    add(parameters, "subject_token", model.getSubjectToken());
    add(parameters, "subject_token_type", model.getSubjectTokenType());
    add(parameters, "requested_token_type", model.getRequestedTokenType());
    Optional.ofNullable(model.getResource()).orElse(List.of()).forEach(r -> add(parameters, "resource", r));
    Optional.ofNullable(model.getAudience()).orElse(List.of()).forEach(a -> add(parameters, "audience", a));
    add(parameters, "scope", model.getScope());
    add(parameters, "actor_token", model.getActorToken());
    if (trim(model.getActorToken()) != null) {
      add(parameters, "actor_token_type", model.getActorTokenType());
    }
    clientAuth.parameters().forEach((name, value) -> {
      if (!"grant_type".equals(name)) {
        parameters.add(name, value);
      }
    });

    final SentTokenExchangeRequest sent = new SentTokenExchangeRequest("POST", op.getTokenEndpoint(),
        clientAuth.headers(), new LinkedHashMap<>(parameters), clientAuth.clientAssertion());
    log.info("Token exchange request to {} as '{}'", op.getTokenEndpoint(), clientId);
    final TokenRequestSender.Result result =
        this.tokenRequestSender.send(op.getTokenEndpoint(), clientAuth.headers(), parameters);

    final List<TokenExchangeChecks.Check> clientAuthChecks = ClientAuthenticationChecks.evaluate(
        op.getTokenEndpoint(), clientAuth.headers(), parameters.toSingleValueMap(), clientAuth.clientAssertion(),
        clientId, ClientAuthenticationChecks.earlierJtis(this.httpSession));
    ClientAuthenticationChecks.rememberJti(this.httpSession, clientAuth.clientAssertion());

    final DecodedToken subjectToken = decode(trim(model.getSubjectToken()));
    final TokenExchangeResult.TokenExchangeResultBuilder builder = TokenExchangeResult.builder()
        .request(sent)
        .clientAuthChecks(clientAuthChecks)
        .body(result.body())
        .error(result.error())
        .subjectToken(subjectToken);
    if (result.error() != null) {
      return builder
          .checks(TokenExchangeChecks.evaluate(parameters, claims(subjectToken), null, null))
          .build();
    }
    final Map<String, Object> response = result.tokenResponse();
    final DecodedToken issued = decode(response != null && response.get("access_token") instanceof final String s
        ? s : null);
    return builder
        .response(response)
        .issuedToken(issued)
        .checks(TokenExchangeChecks.evaluate(parameters, claims(subjectToken), response, claims(issued)))
        .build();
  }

  /**
   * Lists the protected resources that an access token can be sent to.
   *
   * @return the protected resources, by index
   */
  @GetMapping(value = "/protected-resources", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<ProtectedResourceInfo> protectedResources() {
    return IntStream.range(0, this.protectedResources.size())
        .mapToObj(i -> new ProtectedResourceInfo(i, this.protectedResources.get(i).getName(),
            this.protectedResources.get(i).getUrl()))
        .toList();
  }

  /**
   * Sends an access token to a configured protected resource ({@code GET}, Bearer).
   *
   * @param model the protected resource and the access token
   * @return the call
   */
  @PostMapping(value = "/authn/protected-resource", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public ResourceCall callProtectedResource(@Nonnull @RequestBody final ResourceCallModel model) {
    if (model.getIndex() == null || model.getIndex() < 0 || model.getIndex() >= this.protectedResources.size()) {
      return ResourceCall.builder().error("Unknown protected resource").build();
    }
    final String url = this.protectedResources.get(model.getIndex()).getUrl();
    final Map<String, String> headers = new LinkedHashMap<>();
    headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
    Optional.ofNullable(trim(model.getAccessToken()))
        .ifPresent(t -> headers.put(HttpHeaders.AUTHORIZATION, "Bearer " + t));
    final ResourceCall.ResourceCallBuilder call = ResourceCall.builder()
        .request(new UserInfoExchange.Request("GET", url, headers));

    final ResponseEntity<String> response;
    try {
      response = this.client.get().uri(url)
          .headers(h -> headers.forEach(h::set))
          .retrieve()
          .onStatus(status -> status.isError(), (request, errorResponse) -> {
          })
          .toEntity(String.class);
    }
    catch (final Exception e) {
      log.info("Call to protected resource {} failed: {}", url, e.getMessage());
      return call.error("Failed to call %s: %s".formatted(url, OidcController.message(e))).build();
    }
    final Map<String, List<String>> responseHeaders = new LinkedHashMap<>();
    response.getHeaders().forEach((name, values) -> responseHeaders.put(name, List.copyOf(values)));
    Object json = null;
    if (response.getBody() != null) {
      try {
        json = objectMapper.readValue(response.getBody(), Object.class);
      }
      catch (final RuntimeException e) {
        // Not JSON - only the raw body is shown
      }
    }
    log.info("Protected resource {} answered {}", url, response.getStatusCode().value());
    return call.status(response.getStatusCode().value())
        .responseHeaders(responseHeaders)
        .body(response.getBody())
        .json(json)
        .build();
  }

  @Nullable
  private PkiCredential signingCredential(@Nonnull final OidcRp rp) {
    return Optional.ofNullable(
            (OidcController.TokenRequestSettings) this.httpSession.getAttribute(
                OidcController.SESSION_NAME_TOKEN_REQUEST_SETTINGS))
        .orElseGet(() -> new OidcController.TokenRequestSettings(null, null))
        .signingCredential(rp);
  }

  private static boolean isJwtAuth(@Nonnull final String method) {
    return TokenRequestParameterModel.PRIVATE_KEY_JWT.equals(method)
        || TokenRequestParameterModel.CLIENT_SECRET_JWT.equals(method);
  }

  @Nonnull
  private static ModelParameter row(@Nonnull final String value, final boolean included) {
    return ModelParameter.builder().value(value).valuePresent(included).requestBody(false).build();
  }

  private static void add(@Nonnull final MultiValueMap<String, String> parameters, @Nonnull final String name,
      @Nullable final String value) {
    Optional.ofNullable(trim(value)).ifPresent(v -> parameters.add(name, v));
  }

  @Nullable
  private static String trim(@Nullable final String value) {
    return Optional.ofNullable(value).map(String::trim).filter(v -> !v.isEmpty()).orElse(null);
  }

  @Nullable
  private static Map<String, Object> claims(@Nullable final DecodedToken token) {
    return token == null ? null : token.claims();
  }

  /**
   * Decodes a token for display. Nothing is verified.
   *
   * @param token the token
   * @return the header and claims, or {@code null} if the token is missing or not a signed or unsecured JWT
   */
  @Nullable
  static DecodedToken decode(@Nullable final String token) {
    if (token == null) {
      return null;
    }
    try {
      final JWT jwt = JWTParser.parse(token);
      if (jwt instanceof SignedJWT || jwt instanceof PlainJWT) {
        return new DecodedToken(jwt.getHeader().toJSONObject(), jwt.getJWTClaimsSet().toJSONObject());
      }
      return null;
    }
    catch (final Exception e) {
      return null;
    }
  }

  /**
   * The defaults of the token exchange form.
   *
   * @param tokenEndpoint the token endpoint of the OP selected for the authentication
   * @param clientId the client ID of the RP selected for the authentication
   * @param authMethods the client authentication methods that can be selected
   * @param resources the resource identifiers suggested for {@code resource} and {@code audience}
   * @param scopes the scopes suggested for {@code scope}
   */
  public record TokenExchangeDefaults(
      @JsonProperty("token_endpoint") @Nullable String tokenEndpoint,
      @JsonProperty("client_id") @Nullable String clientId,
      @JsonProperty("auth_methods") @Nonnull List<String> authMethods,
      @Nonnull List<String> resources,
      @Nonnull List<String> scopes) {
  }

  /**
   * A token exchange request to send. Empty values are left out.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class TokenExchangeRequestModel {

    @JsonProperty("subject_token")
    private String subjectToken;

    @JsonProperty("subject_token_type")
    private String subjectTokenType;

    @JsonProperty("requested_token_type")
    private String requestedTokenType;

    /** The {@code resource} parameters (RFC 8707) - each is sent as a parameter of its own. */
    private List<String> resource = new ArrayList<>();

    /** The {@code audience} parameters - each is sent as a parameter of its own. */
    private List<String> audience = new ArrayList<>();

    private String scope;

    @JsonProperty("actor_token")
    private String actorToken;

    @JsonProperty("actor_token_type")
    private String actorTokenType;

    /** The client ID - defaults to the RP selected for the authentication. */
    @JsonProperty("client_id")
    private String clientId;

    /** The client authentication method - defaults to {@code private_key_jwt}. */
    @JsonProperty("auth_method")
    private String authMethod;

    /** The client secret, for the {@code client_secret_*} methods. */
    @JsonProperty("client_secret")
    private String clientSecret;
  }

  /**
   * A token exchange request as it was sent.
   *
   * @param method the HTTP method (always {@code POST})
   * @param url the token endpoint
   * @param headers the request headers
   * @param parameters the form parameters, in the order they were sent
   * @param clientAssertion the decoded client assertion, or {@code null} if none was sent
   */
  public record SentTokenExchangeRequest(
      @Nonnull String method,
      @Nonnull String url,
      @Nonnull Map<String, String> headers,
      @Nonnull Map<String, List<String>> parameters,
      @JsonProperty("client_assertion") @Nullable SentTokenRequest.ClientAssertion clientAssertion) {
  }

  /**
   * A decoded JWT.
   *
   * @param header the JOSE header
   * @param claims the claims
   */
  public record DecodedToken(@Nonnull Map<String, Object> header, @Nonnull Map<String, Object> claims) {
  }

  /**
   * The result of a token exchange request.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class TokenExchangeResult {

    /** The request as sent, or {@code null} if it was not sent. */
    private SentTokenExchangeRequest request;

    /** The token response, or {@code null} if none was received. */
    private Map<String, Object> response;

    /** The raw response body. */
    private String body;

    /** Why no token response was received, or {@code null}. */
    private TokenEndpointError error;

    /** The decoded subject token, or {@code null} if it is not a JWT. */
    @JsonProperty("subject_token")
    private DecodedToken subjectToken;

    /** The decoded issued access token, or {@code null} if none was issued or it is not a JWT. */
    @JsonProperty("issued_token")
    private DecodedToken issuedToken;

    /** The checks against the Ena chaining profile. */
    private List<TokenExchangeChecks.Check> checks;

    /** The checks of the client authentication against the SDG OAuth 2.0 profile, section 4.1.1. */
    @JsonProperty("client_auth_checks")
    private List<TokenExchangeChecks.Check> clientAuthChecks;
  }

  /**
   * A configured protected resource.
   *
   * @param index the index, used to select it
   * @param name the name
   * @param url the URL
   */
  public record ProtectedResourceInfo(int index, @Nonnull String name, @Nonnull String url) {
  }

  /**
   * A call to a protected resource.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ResourceCallModel {

    /** The index of the protected resource. */
    private Integer index;

    /** The access token - if empty, no {@code Authorization} header is sent. */
    @JsonProperty("access_token")
    private String accessToken;
  }

  /**
   * A call to a protected resource as it was made.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ResourceCall {

    private UserInfoExchange.Request request;

    private Integer status;

    @JsonProperty("response_headers")
    private Map<String, List<String>> responseHeaders;

    private String body;

    /** The response body as JSON, or {@code null} if it is not JSON. */
    private Object json;

    /** Why no response was received, or {@code null}. */
    private String error;
  }
}
