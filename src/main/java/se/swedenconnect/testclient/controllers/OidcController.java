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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.utils.JoseUtils;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * @author Martin Lindström
 * @author Felix Hellman
 */
@Slf4j
@Controller
public class OidcController {

  private final HttpSession httpSession;
  private final RestClient client;
  private final UserInfoCaller userInfoCaller;

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
    this.client = client;
    this.userInfoCaller = new UserInfoCaller(client);
  }

  @RequestMapping(path = REDIRECTION_URL_BASE + "/{rpSuffix}", method = {RequestMethod.GET, RequestMethod.POST})
  public ModelAndView handleRedirection(@Nonnull final HttpServletRequest request,
      @PathVariable("rpSuffix") @Nonnull final String rp,
      @RequestParam(value = "error", required = false) final String error,
      @RequestParam(value = "error_description", required = false) final String errorDescription,
      @RequestParam(value = "state", required = false) final String state,
      @RequestParam(value = "iss", required = false) final String iss,
      @RequestParam(value = "code", required = false) final String code) throws JOSEException, ParseException {
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

    final PkiCredential credentialForSigning = selectedRp.getCredentials()
        .getCredentialForSigning();

    final JWK jwk = new JwkTransformerFunction().serializable()
        .apply(credentialForSigning);

    final JWSHeader header = new JWSHeader.Builder(JoseUtils.signingAlgorithm(jwk))
        .jwk(jwk.toPublicJWK())
        .keyID(jwk.getKeyID())
        .build();

    final JWTClaimsSet.Builder clientAssertion = new JWTClaimsSet.Builder();

    clientAssertion
        .issuer(selectedRp.getEntityId())
        .subject(selectedRp.getEntityId())
        .audience(selectedOp.getTokenEndpoint())
        .jwtID(UUID.randomUUID().toString())
        .issueTime(Date.from(Instant.now()))
        .expirationTime(Date.from(Instant.now().plusSeconds(300)));

    final SignedJWT assertion = new SignedJWT(header, clientAssertion.build());
    assertion.sign(JoseUtils.signer(credentialForSigning));

    final State sentState = authRequest.getState();

    final MultiValueMap<String, String> tokenBody = new LinkedMultiValueMap<>();
    tokenBody.add("grant_type", "authorization_code");
    tokenBody.add("code", code);
    tokenBody.add("redirect_uri", selectedRp.getMetadata().getRedirectionURI().toASCIIString());
    tokenBody.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    tokenBody.add("client_assertion", assertion.serialize());
    codeVerifier.ifPresent(verifier -> tokenBody.add("code_verifier", verifier.getRight().getValue()));
    final Map<String, String> errorBody = new HashMap<>();
    final RestClient.ResponseSpec.ErrorHandler errorHandler = (a, b) -> {
      final Map<String, String> errorMap =
          (Map<String, String>) objectMapper.readerFor(Map.class).readValue(b.getBody().readAllBytes());
      errorBody.putAll(errorMap);
      throw new RuntimeException("Token exchange error");
    };
    try {
      final Map<String, Object> tokenResponse = this.client.post().uri(selectedOp.getTokenEndpoint())
          .body(tokenBody)
          .header("content-type", "application/x-www-form-urlencoded; charset=UTF-8")
          .retrieve()
          .onStatus(s -> s.value() == 400, errorHandler)
          .toEntity(new ParameterizedTypeReference<Map<String, Object>>() {
          })
          .getBody();

      final String accessToken = (String) tokenResponse.get("access_token");
      final JWTClaimsSet jwtClaims = (JWTClaimsSet) httpSession.getAttribute("jwt_claims");
      final Optional<OIDCClaimsRequest> authClaims = UserInfoEvaluation.requestedClaims(authRequest, jwtClaims);

      final OidcJwtParser.ProtectedJwt idTokenResult =
          OidcJwtParser.parseProtectedJwt((String) tokenResponse.get("id_token"), selectedRp);
      final Map<String, Object> idTokenClaims = idTokenResult.claims();
      // Kept for "Send UserInfo Request", which is made after the response has been removed from the session
      httpSession.setAttribute(SESSION_NAME_ID_TOKEN_CLAIMS, idTokenClaims);

      final boolean callUserInfo = !Boolean.FALSE.equals(httpSession.getAttribute(SESSION_NAME_CALL_USERINFO));
      final UserInfoExchange userInfoExchange = callUserInfo
          ? this.userInfoCaller.call(selectedOp.getUserInfoEndpoint(), accessToken, HttpMethod.GET, selectedRp)
          : null;
      final UserInfoEvaluation userInfo =
          UserInfoEvaluation.evaluate(authRequest, jwtClaims, idTokenClaims, userInfoExchange, false);

      final Map<String, Object> requestParameters = new HashMap<>(Map.of("iss", iss));
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
      final Map<String, Object> responseParameters = new HashMap<>(Map.copyOf(tokenResponse));
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
          .userInfoResult(userInfo.getUserInfoResult())
          .userInfoClaims(userInfo.getUserInfoClaims())
          .userInfoClaimTimes(userInfo.getUserInfoClaimTimes())
          .missingUserInfoClaims(userInfo.getMissingUserInfoClaims())
          .idTokenProtection(idTokenResult.protection())
          .userInfoProtection(userInfo.getUserInfoProtection())
          .responseProtection(ProtectionInfo.builder().format("JSON").build())
          .requestParameters(requestParameters)
          .responseParameters(responseParameters)
          .response(tokenResponse);


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
      return new ModelAndView("redirect:/oidc/redirect/%s?error=%s&error_description=%s"
          .formatted(rp, errorBody.get("error"), errorBody.get("error_description")));
    }
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
