/*
 * Copyright 2025 Sweden Connect
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
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
@AllArgsConstructor
public class OidcController {

  private final HttpSession httpSession;
  private final RestClient client;

  public static final String SESSION_NAME_OIDC_RESPONSE = "sctc.oidcResponse";

  /**
   * The base path for the redirection URLs.
   */
  public static final String REDIRECTION_URL_BASE = "/oidc/redirect";

  @RequestMapping(path = REDIRECTION_URL_BASE + "/{rpSuffix}", method = {RequestMethod.GET, RequestMethod.POST})
  public ModelAndView handleRedirection(@Nonnull final HttpServletRequest request,
                                        @PathVariable("rpSuffix") @Nonnull final String rp,
                                        @RequestParam(value = "error", required = false) final String error,
                                        @RequestParam(value = "error_description", required = false) final String errorDescription,
                                        @RequestParam(value = "state", required = false) final String state,
                                        @RequestParam(value = "iss", required = false) final String iss,
                                        @RequestParam(value = "code", required = false) final String code) throws JOSEException,
      ParseException, JsonProcessingException {
    final AuthenticationRequest authRequest = (AuthenticationRequest) httpSession.getAttribute("auth_request");
    final OidcOp selectedOp = (OidcOp) httpSession.getAttribute("selected_op");
    final OidcRp selectedRp = (OidcRp) httpSession.getAttribute("selected_rp");

    if (Objects.nonNull(error) || Objects.nonNull(errorDescription)) {
      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE,
          OIDCResponse.builder()
              .errors(List.of("error:%s Error Description:%s".formatted(error, errorDescription)))
              .opError(true)
              .authorizationRequest(authRequest.toHTTPRequest().getURI().toASCIIString())
              .build()
      );
      return new ModelAndView("redirect:/");
    }

    final Optional<Pair<CodeChallengeMethod, CodeVerifier>> codeVerifier = Optional.ofNullable(
        (Pair<CodeChallengeMethod, CodeVerifier>) httpSession.getAttribute("code_verifier")
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
          (Map<String, String>) new ObjectMapper().readerFor(Map.class).readValue(b.getBody().readAllBytes());
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

      final Map<String, Object> userInfo = this.client.get().uri(selectedOp.getUserInfoEndpoint())
          .header("Authorization", "Bearer %s".formatted(tokenResponse.get("access_token")))
          .retrieve()
          .toEntity(new ParameterizedTypeReference<Map<String, Object>>() {
          })
          .getBody();

      final Optional<OIDCClaimsRequest> authClaims = Optional.ofNullable(authRequest.getOIDCClaims())
          .or(() -> {
            final JWTClaimsSet jwtClaims = (JWTClaimsSet) httpSession.getAttribute("jwt_claims");
            if (Objects.isNull(jwtClaims)) {
              return Optional.empty();
            }
            try {
              final Map<String, Object> claims = jwtClaims.toJSONObject();
              if (Objects.isNull(claims)) {
                return Optional.empty();
              }
              return Optional.of(OIDCClaimsRequest.parse(new JSONObject(claims)));
            } catch (final com.nimbusds.oauth2.sdk.ParseException e) {
              throw new RuntimeException(e);
            }
          });

      final Map<String, Object> idTokenClaims = SignedJWT.parse((String) tokenResponse.get("id_token")).getJWTClaimsSet().toJSONObject();
      final Map<String, Object> requestParameters = new HashMap<>(Map.of("iss", iss));
      Optional.ofNullable(state).ifPresent(s -> requestParameters.put("state", s));

      Optional.ofNullable(authRequest.getRequestObject()).ifPresent(obj -> requestParameters.put("request_object", obj.serialize()));
      Optional.ofNullable(authRequest.getNonce()).ifPresent(nonce1 -> requestParameters.put("nonce", nonce1.getValue()));
      Optional.ofNullable(authRequest.getACRValues()).ifPresent(acrs -> requestParameters.put("acr_values", acrs));
      Optional.ofNullable(authRequest.getRedirectionURI()).ifPresent(redirection -> requestParameters.put("redirect_uri", redirection));
      Optional.ofNullable(httpSession.getAttribute("jwt_claims")).map(JWTClaimsSet.class::cast).ifPresent(jwt -> {
        try {
          requestParameters.put("jwt_claims", new ObjectMapper().writeValueAsString(jwt.toJSONObject()));
        } catch (JsonProcessingException e) {
          throw new RuntimeException(e);
        }
      });
      Optional.ofNullable(httpSession.getAttribute("plain_jwt")).map(JWT.class::cast).ifPresent(jwt -> requestParameters.put(
          "plain_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("encrypted_plain_jwt")).map(JWT.class::cast).ifPresent(jwt -> requestParameters.put(
          "encrypted_plain_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("signed_jwt")).map(JWT.class::cast).ifPresent(jwt -> requestParameters.put(
          "signed_jwt", jwt.serialize()));
      Optional.ofNullable(httpSession.getAttribute("encrypted_signed_jwt")).map(JWT.class::cast).ifPresent(jwt -> requestParameters.put(
          "encrypted_signed_jwt", jwt.serialize()));

      requestParameters.put("token_endpoint", selectedOp.getTokenEndpoint());
      requestParameters.put("userInfo_endpoint", selectedOp.getUserInfoEndpoint());
      requestParameters.put("auth_endpoint", selectedOp.getAuthorizationEndpoint());
      final Map<String, Object> responseParameters = new HashMap<>(Map.copyOf(tokenResponse));
      Optional.ofNullable(state).ifPresent(s -> responseParameters.put("state", s));
      Optional.ofNullable(iss).ifPresent(s -> responseParameters.put("iss", s));
      Optional.ofNullable(code).ifPresent(s -> responseParameters.put("code", s));

      final OIDCResponse.OIDCResponseBuilder responseBuilder = OIDCResponse.builder()
          .accessTokenClaims(SignedJWT.parse((String) tokenResponse.get("access_token")).getJWTClaimsSet().toJSONObject())
          .idTokenClaims(idTokenClaims)
          .authorizationRequest(authRequest.toHTTPRequest().getURI().toASCIIString())
          .userInfoClaims(userInfo)
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
        final ClaimsSetRequest userInfoClaimsRequest = oidcClaimsRequest.getUserInfoClaimsRequest();
        if (Objects.nonNull(userInfoClaimsRequest)) {
          final JSONObject missingUserInfoClaims = userInfoClaimsRequest.toJSONObject();

          userInfo.forEach((key, value) -> missingUserInfoClaims.remove(key));
          responseBuilder.missingUserInfoClaims(missingUserInfoClaims);
        }
      }


      Optional.ofNullable((String) tokenResponse.get("refresh_token"))
          .ifPresent(rt -> httpSession.setAttribute("refresh_token", rt));

      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE,
          responseBuilder
              .build());

      return new ModelAndView("redirect:/");
    } catch (final RuntimeException e) {
      return new ModelAndView("redirect:/oidc/redirect/%s?error=%s&error_description=%s"
          .formatted(rp, errorBody.get("error"), errorBody.get("error_description")));
    }
  }
}
