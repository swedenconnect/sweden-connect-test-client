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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
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
import org.springframework.http.ResponseEntity;
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
import se.swedenconnect.testclient.oidc.ScopeClaimRegistry;
import se.swedenconnect.testclient.utils.JoseUtils;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.ArrayList;
import java.util.Arrays;
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

  /** Mapper used for the JSON bodies that are exchanged with the OP (token and UserInfo endpoints). */
  private static final ObjectMapper objectMapper = JsonMapper.builder().build();

  @RequestMapping(path = REDIRECTION_URL_BASE + "/{rpSuffix}", method = {RequestMethod.GET, RequestMethod.POST})
  public ModelAndView handleRedirection(@Nonnull final HttpServletRequest request,
                                        @PathVariable("rpSuffix") @Nonnull final String rp,
                                        @RequestParam(value = "error", required = false) final String error,
                                        @RequestParam(value = "error_description", required = false) final String errorDescription,
                                        @RequestParam(value = "state", required = false) final String state,
                                        @RequestParam(value = "iss", required = false) final String iss,
                                        @RequestParam(value = "code", required = false) final String code) throws JOSEException,
      ParseException {
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

      final ResponseEntity<String> userInfoResponse = this.client.get().uri(selectedOp.getUserInfoEndpoint())
          .header("Authorization", "Bearer %s".formatted(tokenResponse.get("access_token")))
          .accept(MediaType.APPLICATION_JSON, MediaType.valueOf("application/jwt"))
          .retrieve()
          .toEntity(String.class);

      final ProtectedJwt userInfoResult = this.parseUserInfo(userInfoResponse, selectedRp);
      final Map<String, Object> userInfo = userInfoResult.claims();

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

      final ProtectedJwt idTokenResult =
          this.parseProtectedJwt((String) tokenResponse.get("id_token"), selectedRp);
      final Map<String, Object> idTokenClaims = idTokenResult.claims();
      final Map<String, Object> requestParameters = new HashMap<>(Map.of("iss", iss));
      Optional.ofNullable(state).ifPresent(s -> requestParameters.put("state", s));

      Optional.ofNullable(authRequest.getRequestObject()).ifPresent(obj -> requestParameters.put("request_object", obj.serialize()));
      Optional.ofNullable(authRequest.getNonce()).ifPresent(nonce1 -> requestParameters.put("nonce", nonce1.getValue()));
      Optional.ofNullable(authRequest.getACRValues()).ifPresent(acrs -> requestParameters.put("acr_values", acrs));
      Optional.ofNullable(authRequest.getRedirectionURI()).ifPresent(redirection -> requestParameters.put("redirect_uri", redirection));
      Optional.ofNullable(httpSession.getAttribute("jwt_claims")).map(JWTClaimsSet.class::cast).ifPresent(
          jwt -> requestParameters.put("jwt_claims", objectMapper.writeValueAsString(jwt.toJSONObject())));
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

      final String accessToken = (String) tokenResponse.get("access_token");

      final OIDCResponse.OIDCResponseBuilder responseBuilder = OIDCResponse.builder()
          .accessToken(accessToken)
          .accessTokenClaims(accessTokenClaims(accessToken))
          .scopeValidation(validateScopes(requestedScopes(authRequest), idTokenClaims, userInfo))
          .idTokenClaims(idTokenClaims)
          .authorizationRequest(authRequest.toHTTPRequest().getURI().toASCIIString())
          .userInfoClaims(userInfo)
          .idTokenProtection(idTokenResult.protection())
          .userInfoProtection(userInfoResult.protection())
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
        final ClaimsSetRequest userInfoClaimsRequest = oidcClaimsRequest.getUserInfoClaimsRequest();
        if (Objects.nonNull(userInfoClaimsRequest)) {
          final JSONObject missingUserInfoClaims = userInfoClaimsRequest.toJSONObject();

          userInfo.forEach((key, value) -> missingUserInfoClaims.remove(key));
          responseBuilder.missingUserInfoClaims(missingUserInfoClaims);
        }
      }


      httpSession.setAttribute(SESSION_NAME_OIDC_RESPONSE,
          responseBuilder
              .build());

      return new ModelAndView("redirect:/");
    } catch (final RuntimeException e) {
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
   * The claims of a JWT together with a description of how it was protected.
   *
   * @param claims the claims of the JWT (empty if it could not be parsed or decrypted)
   * @param protection how the JWT was protected
   */
  private record ProtectedJwt(Map<String, Object> claims, ProtectionInfo protection) {
  }

  /**
   * Parses a UserInfo response, which is either a plain JSON object or a JWT (signed and/or encrypted).
   *
   * @param response the UserInfo response
   * @param rp the relying party (holding the keys needed for decryption)
   * @return the UserInfo claims along with how they were protected
   */
  private ProtectedJwt parseUserInfo(final ResponseEntity<String> response, final OidcRp rp) {
    final String body = Optional.ofNullable(response.getBody()).orElse("");
    final MediaType contentType = response.getHeaders().getContentType();
    if (Objects.nonNull(contentType) && contentType.getSubtype().toLowerCase().contains("jwt")) {
      return this.parseProtectedJwt(body, rp);
    }
    try {
      final Map<String, Object> claims =
          objectMapper.readerFor(Map.class).readValue(body);
      return new ProtectedJwt(new HashMap<>(claims), ProtectionInfo.builder().format("JSON").build());
    }
    catch (final Exception e) {
      log.warn("Failed to parse UserInfo response", e);
      return new ProtectedJwt(new HashMap<>(), ProtectionInfo.builder()
          .note("Failed to parse UserInfo response: %s".formatted(e.getMessage()))
          .build());
    }
  }

  /**
   * Parses a JWT that may be signed, encrypted, encrypted and signed, or neither, and reports how it was protected.
   *
   * @param token the serialized JWT
   * @param rp the relying party (holding the keys needed for decryption)
   * @return the claims of the JWT along with how it was protected
   */
  private ProtectedJwt parseProtectedJwt(final String token, final OidcRp rp) {
    final ProtectionInfo.ProtectionInfoBuilder protection = ProtectionInfo.builder();
    if (Objects.isNull(token) || token.isBlank()) {
      return new ProtectedJwt(new HashMap<>(), ProtectionInfo.builder().note("Not present in the response").build());
    }
    try {
      JWT jwt = JWTParser.parse(token);
      if (jwt instanceof final EncryptedJWT encrypted) {
        final JWEHeader header = encrypted.getHeader();
        protection.encrypted(true)
            .format("Encrypted JWT")
            .encryptionAlgorithm(Optional.ofNullable(header.getAlgorithm()).map(Object::toString).orElse(null))
            .encryptionMethod(
                Optional.ofNullable(header.getEncryptionMethod()).map(EncryptionMethod::getName).orElse(null))
            .encryptionKeyId(header.getKeyID());

        final Optional<JWT> decrypted = this.decrypt(encrypted, rp);
        if (decrypted.isEmpty()) {
          return new ProtectedJwt(new HashMap<>(), protection
              .note("Could not be decrypted with any of the client's encryption keys")
              .build());
        }
        jwt = decrypted.get();
      }
      if (jwt instanceof final SignedJWT signed) {
        final JWSHeader header = signed.getHeader();
        protection.signed(true)
            .signatureAlgorithm(Optional.ofNullable(header.getAlgorithm()).map(Object::toString).orElse(null))
            .signatureKeyId(header.getKeyID())
            .signatureType(Optional.ofNullable(header.getType()).map(JOSEObjectType::toString).orElse(null));
      }
      final ProtectionInfo built = protection.build();
      if (Objects.isNull(built.getFormat())) {
        built.setFormat(built.isSigned() ? "Signed JWT" : "Plain JWT");
      }
      return new ProtectedJwt(new HashMap<>(jwt.getJWTClaimsSet().toJSONObject()), built);
    }
    catch (final ParseException e) {
      log.warn("Failed to parse JWT", e);
      return new ProtectedJwt(new HashMap<>(),
          protection.note("Failed to parse: %s".formatted(e.getMessage())).build());
    }
  }

  /**
   * Gets the scopes that were requested, either as a request parameter or in the request object.
   *
   * @param authRequest the authentication request
   * @return the requested scopes
   */
  private List<String> requestedScopes(final AuthenticationRequest authRequest) {
    final List<String> scopes = new ArrayList<>(
        Optional.ofNullable(authRequest.getScope()).map(Scope::toStringList).orElseGet(List::of));

    Optional.ofNullable(httpSession.getAttribute("jwt_claims"))
        .map(JWTClaimsSet.class::cast)
        .map(claims -> claims.getClaim("scope"))
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .ifPresent(scope -> Arrays.stream(scope.split("\\s+"))
            .filter(s -> !s.isBlank())
            .filter(s -> !scopes.contains(s))
            .forEach(scopes::add));

    return scopes;
  }

  /**
   * Checks, for each requested scope, whether the claims that the scope is defined to deliver were received.
   *
   * @param scopes the requested scopes
   * @param idTokenClaims the claims of the ID Token
   * @param userInfoClaims the claims received from the UserInfo endpoint
   * @return one result per requested scope
   */
  private static List<ScopeValidationResult> validateScopes(final List<String> scopes,
      final Map<String, Object> idTokenClaims, final Map<String, Object> userInfoClaims) {

    return scopes.stream()
        .map(scope -> {
          final Optional<List<ScopeClaimRegistry.ScopeClaim>> registered = ScopeClaimRegistry.getClaims(scope);
          if (registered.isEmpty()) {
            return ScopeValidationResult.builder()
                .scope(scope)
                .status(ScopeValidationResult.Status.UNKNOWN)
                .message("The scope is not defined by the Swedish OpenID Connect or Sweden Connect specifications")
                .build();
          }
          final List<ScopeClaimRegistry.ScopeClaim> scopeClaims = registered.get();
          if (scopeClaims.isEmpty()) {
            return ScopeValidationResult.builder()
                .scope(scope)
                .status(ScopeValidationResult.Status.NO_CLAIMS)
                .message("The scope does not by itself deliver any claims")
                .build();
          }

          final List<ScopeValidationResult.ClaimValidationResult> results = scopeClaims.stream()
              .map(claim -> {
                final List<String> receivedIn = new ArrayList<>();
                if (Objects.nonNull(idTokenClaims) && idTokenClaims.containsKey(claim.name())) {
                  receivedIn.add(ScopeClaimRegistry.Location.ID_TOKEN.getDisplayName());
                }
                if (Objects.nonNull(userInfoClaims) && userInfoClaims.containsKey(claim.name())) {
                  receivedIn.add(ScopeClaimRegistry.Location.USER_INFO.getDisplayName());
                }
                return ScopeValidationResult.ClaimValidationResult.builder()
                    .claim(claim.name())
                    .expectedLocation(claim.location().getDisplayName())
                    .requirement(claim.requirement().name())
                    .received(!receivedIn.isEmpty())
                    .receivedIn(receivedIn.isEmpty() ? null : String.join(", ", receivedIn))
                    .build();
              })
              .toList();

          final List<String> missingMandatory = results.stream()
              .filter(r -> ScopeClaimRegistry.Requirement.MANDATORY.name().equals(r.getRequirement()))
              .filter(r -> !r.isReceived())
              .map(ScopeValidationResult.ClaimValidationResult::getClaim)
              .toList();

          final List<ScopeValidationResult.ClaimValidationResult> oneOf = results.stream()
              .filter(r -> ScopeClaimRegistry.Requirement.ONE_OF.name().equals(r.getRequirement()))
              .toList();
          final long oneOfReceived = oneOf.stream()
              .filter(ScopeValidationResult.ClaimValidationResult::isReceived)
              .count();

          final ScopeValidationResult.ScopeValidationResultBuilder builder = ScopeValidationResult.builder()
              .scope(scope)
              .claims(results);

          if (!missingMandatory.isEmpty()) {
            return builder
                .status(ScopeValidationResult.Status.MISSING)
                .message("Missing claim(s): %s".formatted(String.join(", ", missingMandatory)))
                .build();
          }
          if (!oneOf.isEmpty() && oneOfReceived == 0) {
            return builder
                .status(ScopeValidationResult.Status.MISSING)
                .message("None of the mutually exclusive claims of the scope was received")
                .build();
          }
          if (oneOfReceived > 1) {
            return builder
                .status(ScopeValidationResult.Status.WARNING)
                .message("The claims of the scope are mutually exclusive, but more than one was received")
                .build();
          }
          return builder.status(ScopeValidationResult.Status.OK).build();
        })
        .toList();
  }

  /**
   * Attempts to decrypt an encrypted JWT using the encryption credentials of the relying party.
   *
   * @param encrypted the encrypted JWT
   * @param rp the relying party
   * @return the decrypted JWT - a {@link SignedJWT} if the payload is a nested signed JWT - or an empty
   *     {@link Optional} if decryption failed
   */
  private Optional<JWT> decrypt(final EncryptedJWT encrypted, final OidcRp rp) {
    for (final PkiCredential credential : rp.getCredentials().getCredentialsForEncryption()) {
      try {
        encrypted.decrypt(JoseUtils.decrypter(credential));
        return Optional.of(Optional.ofNullable(encrypted.getPayload().toSignedJWT())
            .map(JWT.class::cast)
            .orElse(encrypted));
      }
      catch (final Exception e) {
        log.debug("Failed to decrypt JWT using credential '{}'", credential.getName(), e);
      }
    }
    return Optional.empty();
  }
}
