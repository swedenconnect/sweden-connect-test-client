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

import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * @author Martin Lindström
 * @author Felix Hellman
 */
@Slf4j
@Controller
public class OidcController {

  private final HttpSession httpSession;
  private final UserInfoCaller userInfoCaller;
  private final TokenRequestSender tokenRequestSender;

  public static final String SESSION_NAME_OIDC_RESPONSE = "sctc.oidcResponse";

  /**
   * Whether UserInfo is called automatically after the token request ({@link Boolean}). It is set for each
   * authentication request that is sent - if missing, UserInfo is called.
   */
  public static final String SESSION_NAME_CALL_USERINFO = "sctc.oidcCallUserInfo";

  /**
   * The claims of the ID token of the latest authentication. Unlike {@link #SESSION_NAME_OIDC_RESPONSE} they remain in
   * the session after the result has been displayed, so that a UserInfo request sent from the result can be
   * evaluated.
   */
  public static final String SESSION_NAME_ID_TOKEN_CLAIMS = "sctc.oidcIdTokenClaims";

  /**
   * The authentication request as it was sent - its method, URL and form parameters, see
   * {@link SentAuthorizationRequest}. It may differ from what the request object describes.
   */
  public static final String SESSION_NAME_SENT_AUTH_REQUEST = "sent_auth_request";

  /**
   * The token request settings of the latest authentication request ({@link TokenRequestSettings}). They are set for
   * each authentication request that is sent - if missing, the token request is sent with the defaults.
   */
  public static final String SESSION_NAME_TOKEN_REQUEST_SETTINGS = "sctc.oidcTokenRequestSettings";

  /**
   * The base path for the redirection URLs.
   */
  public static final String REDIRECTION_URL_BASE = "/oidc/redirect";

  /** Mapper used for the JSON bodies that are exchanged with the token endpoint. */
  private static final ObjectMapper objectMapper = JsonMapper.builder().build();

  /**
   * Constructor.
   *
   * @param httpSession the HTTP session
   * @param client the HTTP client used against the token and UserInfo endpoints
   */
  public OidcController(@Nonnull final HttpSession httpSession, @Nonnull final RestClient client) {
    this.httpSession = httpSession;
    this.userInfoCaller = new UserInfoCaller(client);
    this.tokenRequestSender = new TokenRequestSender(client);
  }

  @RequestMapping(path = REDIRECTION_URL_BASE + "/{rpSuffix}", method = {RequestMethod.GET, RequestMethod.POST})
  public ModelAndView handleRedirection(@Nonnull final HttpServletRequest request,
      @PathVariable("rpSuffix") @Nonnull final String rp,
      @RequestParam(value = "error", required = false) final String error,
      @RequestParam(value = "error_description", required = false) final String errorDescription,
      @RequestParam(value = "state", required = false) final String state,
      @RequestParam(value = "iss", required = false) final String iss,
      @RequestParam(value = "code", required = false) final String code) {
    final AuthenticationRequest authRequest = (AuthenticationRequest) httpSession.getAttribute("auth_request");
    final OidcOp selectedOp = (OidcOp) httpSession.getAttribute("selected_op");
    final OidcRp selectedRp = (OidcRp) httpSession.getAttribute("selected_rp");

    if (Objects.nonNull(error) || Objects.nonNull(errorDescription)) {
      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE,
          OIDCResponse.builder()
              .errors(List.of("error:%s Error Description:%s".formatted(error, errorDescription)))
              .opError(true)
              .authorizationRequest(this.sentRequest(authRequest))
              .build()
      );
      return new ModelAndView("redirect:/");
    }

    final Optional<Pair<CodeChallengeMethod, CodeVerifier>> codeVerifier = Optional.ofNullable(
        (Pair<CodeChallengeMethod, CodeVerifier>) httpSession.getAttribute(
            AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE)
    );

    final TokenRequestSettings tokenRequestSettings = Optional.ofNullable(
            (TokenRequestSettings) httpSession.getAttribute(SESSION_NAME_TOKEN_REQUEST_SETTINGS))
        .orElseGet(() -> new TokenRequestSettings(null, null));
    final TokenRequestParameterModel settings = TokenRequestParameterModel.withDefaults(
        tokenRequestSettings.settings(),
        TokenRequestParameterModel.defaults(selectedRp.getEntityId(),
            Optional.ofNullable(selectedRp.getMetadata().getRedirectionURI()).map(URI::toASCIIString).orElse(null),
            selectedOp.getIssuer()));

    final SentTokenRequest tokenRequest;
    try {
      tokenRequest = TokenRequestFactory.create(settings, selectedOp.getTokenEndpoint(), code,
          codeVerifier.map(v -> v.getRight().getValue()).orElse(null),
          tokenRequestSettings.signingCredential(selectedRp), Instant.now());
    }
    catch (final TokenRequestException e) {
      log.info("Token request for '{}' not sent: {}", selectedRp.getEntityId(), e.getMessage());
      return this.tokenEndpointError(authRequest, null, TokenEndpointError.builder()
          .message("The token request was not sent to the token endpoint %s. %s."
              .formatted(selectedOp.getTokenEndpoint(), e.getMessage()))
          .build());
    }

    final TokenRequestSender.Result tokenResult = this.tokenRequestSender.send(tokenRequest);
    if (tokenResult.error() != null) {
      return this.tokenEndpointError(authRequest, tokenRequest, tokenResult.error());
    }
    final Map<String, Object> tokenResponse = Objects.requireNonNull(tokenResult.tokenResponse());

    // Neither a missing iss nor a null value in the token response stops the processing - they are reported as
    // errors on the result page along with everything that could be read.
    final List<String> errors = new ArrayList<>();
    if (iss == null && selectedOp.advertisesIssParameter()) {
      errors.add("The authorization response contained no iss parameter, although %s advertises %s"
          .formatted(selectedOp.getEntityId(), OidcOp.ISS_PARAMETER_SUPPORTED));
    }
    tokenResponse.entrySet().stream()
        .filter(entry -> entry.getValue() == null)
        .forEach(entry -> errors.add(
            "The token response parameter '%s' has the JSON value null".formatted(entry.getKey())));

    try {
      final String accessToken = tokenResponse.get("access_token") instanceof final String s ? s : null;
      final JWTClaimsSet jwtClaims = (JWTClaimsSet) httpSession.getAttribute("jwt_claims");
      final Optional<OIDCClaimsRequest> authClaims = UserInfoEvaluation.requestedClaims(authRequest, jwtClaims);

      final OidcJwtParser.ProtectedJwt idTokenResult = OidcJwtParser.parseProtectedJwt(
          tokenResponse.get("id_token") instanceof final String s ? s : null, selectedRp);
      final Map<String, Object> idTokenClaims = idTokenResult.claims();
      // Kept for "Send UserInfo Request", which is made after the response has been removed from the session
      httpSession.setAttribute(SESSION_NAME_ID_TOKEN_CLAIMS, idTokenClaims);

      final boolean callUserInfo = !Boolean.FALSE.equals(httpSession.getAttribute(SESSION_NAME_CALL_USERINFO));
      final UserInfoExchange userInfoExchange = callUserInfo
          ? this.userInfoCaller.call(selectedOp.getUserInfoEndpoint(), accessToken, HttpMethod.GET, selectedRp)
          : null;
      final UserInfoEvaluation userInfo =
          UserInfoEvaluation.evaluate(authRequest, jwtClaims, idTokenClaims, userInfoExchange, false);

      final Map<String, Object> requestParameters = new HashMap<>();
      Optional.ofNullable(iss).ifPresent(i -> requestParameters.put("iss", i));
      Optional.ofNullable(state).ifPresent(s -> requestParameters.put("state", s));

      Optional.ofNullable(authRequest.getRequestObject())
          .ifPresent(obj -> requestParameters.put("request_object", obj.serialize()));
      Optional.ofNullable(authRequest.getNonce())
          .ifPresent(nonce1 -> requestParameters.put("nonce", nonce1.getValue()));
      Optional.ofNullable(authRequest.getACRValues()).ifPresent(acrs -> requestParameters.put("acr_values", acrs));
      Optional.ofNullable(authRequest.getRedirectionURI())
          .ifPresent(redirection -> requestParameters.put("redirect_uri", redirection));
      Optional.ofNullable(httpSession.getAttribute("jwt_claims")).map(JWTClaimsSet.class::cast).ifPresent(
          jwt -> requestParameters.put("jwt_claims", objectMapper.writeValueAsString(jwt.toJSONObject())));
      Optional.ofNullable(httpSession.getAttribute("plain_jwt")).map(JWT.class::cast)
          .ifPresent(jwt -> requestParameters.put("plain_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("encrypted_plain_jwt")).map(JWT.class::cast)
          .ifPresent(jwt -> requestParameters.put("encrypted_plain_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("signed_jwt")).map(JWT.class::cast)
          .ifPresent(jwt -> requestParameters.put("signed_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("encrypted_signed_jwt")).map(JWT.class::cast)
          .ifPresent(jwt -> requestParameters.put("encrypted_signed_jwt", jwt.serialize()));

      requestParameters.put("token_endpoint", selectedOp.getTokenEndpoint());
      requestParameters.put("userInfo_endpoint", selectedOp.getUserInfoEndpoint());
      requestParameters.put("auth_endpoint", selectedOp.getAuthorizationEndpoint());
      // A HashMap, not Map.copyOf - a token response parameter may have the JSON value null
      final Map<String, Object> responseParameters = new HashMap<>(tokenResponse);
      Optional.ofNullable(state).ifPresent(s -> responseParameters.put("state", s));
      Optional.ofNullable(iss).ifPresent(s -> responseParameters.put("iss", s));
      Optional.ofNullable(code).ifPresent(s -> responseParameters.put("code", s));

      final Map<String, Object> accessTokenClaims = accessTokenClaims(accessToken);
      final OIDCResponse.OIDCResponseBuilder responseBuilder = OIDCResponse.builder()
          .accessToken(accessToken)
          .accessTokenClaims(accessTokenClaims)
          .accessTokenClaimTimes(ClaimTimes.of(accessTokenClaims))
          .scopeValidation(userInfo.getScopeValidation())
          .idTokenClaims(idTokenClaims)
          .idTokenClaimTimes(ClaimTimes.of(idTokenClaims))
          .authorizationRequest(this.sentRequest(authRequest))
          .tokenRequest(tokenRequest)
          .userInfoResult(userInfo.getUserInfoResult())
          .userInfoClaims(userInfo.getUserInfoClaims())
          .userInfoClaimTimes(userInfo.getUserInfoClaimTimes())
          .missingUserInfoClaims(userInfo.getMissingUserInfoClaims())
          .idTokenProtection(idTokenResult.protection())
          .userInfoProtection(userInfo.getUserInfoProtection())
          .responseProtection(ProtectionInfo.builder().format("JSON").build())
          .requestParameters(requestParameters)
          .responseParameters(responseParameters)
          .response(tokenResponse)
          .tokenResponseBody(tokenResult.body())
          .errors(errors.isEmpty() ? null : errors);


      if (authClaims.isPresent()) {
        final OIDCClaimsRequest oidcClaimsRequest = authClaims.get();
        final ClaimsSetRequest idTokenClaimsRequest = oidcClaimsRequest.getIDTokenClaimsRequest();
        if (Objects.nonNull(idTokenClaimsRequest)) {
          final JSONObject missingIdTokenClaims = idTokenClaimsRequest.toJSONObject();

          idTokenClaims.forEach((key, value) -> missingIdTokenClaims.remove(key));
          responseBuilder.missingIdTokenClaims(missingIdTokenClaims);
        }
      }


      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE,
          responseBuilder
              .build());

      return new ModelAndView("redirect:/");
    }
    catch (final RuntimeException e) {
      log.info("Failed to process the token response from {}: {}", selectedOp.getTokenEndpoint(), message(e));
      log.debug("Failed to process the token response from {}", selectedOp.getTokenEndpoint(), e);
      errors.addFirst("The token response from %s could not be processed: %s"
          .formatted(selectedOp.getTokenEndpoint(), message(e)));
      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE, OIDCResponse.builder()
          .errors(errors)
          .authorizationRequest(this.sentRequest(authRequest))
          .tokenRequest(tokenRequest)
          .response(tokenResponse)
          .tokenResponseBody(tokenResult.body())
          .build());
      return new ModelAndView("redirect:/");
    }
  }

  /**
   * Stores the result of a token request that did not give a token response, and redirects to the result page.
   *
   * @param authRequest the authentication request
   * @param tokenRequest the token request as it was sent, or {@code null} if it could not be sent
   * @param error why no token response was received
   * @return the redirect to the result page
   */
  @Nonnull
  private ModelAndView tokenEndpointError(@Nonnull final AuthenticationRequest authRequest,
      @Nullable final SentTokenRequest tokenRequest, @Nonnull final TokenEndpointError error) {
    httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE, OIDCResponse.builder()
        .errors(error.toMessages())
        .tokenError(error)
        .authorizationRequest(this.sentRequest(authRequest))
        .tokenRequest(tokenRequest)
        .tokenResponseBody(error.getBody())
        .build());
    return new ModelAndView("redirect:/");
  }

  /**
   * The token request settings of an authentication request, recorded when the request is generated.
   *
   * @param settings the token request settings ({@code null} for the defaults)
   * @param keyOptionsSignKey the signing key selected under "Key options" - the key that signs a
   *     {@code private_key_jwt} client assertion, as a key ID and the credential for it ({@code null} for the RP's
   *     registered signing key)
   */
  public record TokenRequestSettings(@Nullable TokenRequestParameterModel settings,
      @Nullable Pair<String, PkiCredential> keyOptionsSignKey) {

    /**
     * Gets the credential that signs a {@code private_key_jwt} client assertion.
     *
     * @param rp the RP
     * @return the credential, or {@code null} if the key selected under "Key options" is not available
     */
    @Nullable
    public PkiCredential signingCredential(@Nonnull final OidcRp rp) {
      if (this.keyOptionsSignKey == null) {
        return Optional.ofNullable(rp.getCredentials()).map(ClientCredentials::getCredentialForSigning).orElse(null);
      }
      return this.keyOptionsSignKey.getRight();
    }
  }

  /**
   * Gets the message of an error. An error without a message is named by its type - so that nothing is reported as
   * "null".
   *
   * @param e the error
   * @return the message, or the name of the error type
   */
  @Nonnull
  static String message(@Nonnull final Throwable e) {
    return Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName());
  }

  /**
   * Extracts the claims of an access token. The access token is not required to be a JWT - if it is an opaque string
   * an empty map is returned.
   *
   * @param accessToken the raw access token
   * @return the claims of the access token, or an empty map if it is not a JWT
   */
  private static Map<String, Object> accessTokenClaims(final String accessToken) {
    if (Objects.isNull(accessToken)) {
      return Map.of();
    }
    try {
      return SignedJWT.parse(accessToken).getJWTClaimsSet().toJSONObject();
    }
    catch (final ParseException e) {
      log.debug("Access token is not a signed JWT - treating it as an opaque token");
      return Map.of();
    }
  }

  /**
   * Gets the authentication request as it was sent. If it was not recorded, it is taken to be a GET of the request.
   *
   * @param authRequest the authentication request
   * @return the sent request
   */
  private SentAuthorizationRequest sentRequest(final AuthenticationRequest authRequest) {
    return Optional.ofNullable((SentAuthorizationRequest) this.httpSession.getAttribute(SESSION_NAME_SENT_AUTH_REQUEST))
        .orElseGet(() -> new SentAuthorizationRequest(SentAuthorizationRequest.Method.GET,
            authRequest.toHTTPRequest().getURI().toASCIIString(), null));
  }
}
