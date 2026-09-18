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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.utils.JoseUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

import static se.swedenconnect.testclient.controllers.TokenRequestParameterModel.CLIENT_SECRET_BASIC;
import static se.swedenconnect.testclient.controllers.TokenRequestParameterModel.CLIENT_SECRET_JWT;
import static se.swedenconnect.testclient.controllers.TokenRequestParameterModel.CLIENT_SECRET_POST;
import static se.swedenconnect.testclient.controllers.TokenRequestParameterModel.NONE;
import static se.swedenconnect.testclient.controllers.TokenRequestParameterModel.PRIVATE_KEY_JWT;

/**
 * Builds the token request that is sent when the OP redirects back with an authorization code, from the token request
 * settings of the authentication request.
 * <p>
 * The settings may produce a request that a compliant client would never send - that is the purpose. Only when the
 * request cannot be built at all, e.g., because the client assertion cannot be signed, is a
 * {@link TokenRequestException} thrown.
 * </p>
 *
 * @author Martin Lindström
 */
public final class TokenRequestFactory {

  /** The client authentication methods that are supported. */
  public static final List<String> AUTH_METHODS =
      List.of(PRIVATE_KEY_JWT, CLIENT_SECRET_JWT, CLIENT_SECRET_POST, CLIENT_SECRET_BASIC, NONE);

  /** How long a client assertion that the test client fills in is valid. */
  static final long ASSERTION_LIFETIME_SECONDS = 300;

  /** A typed {@code iat} or {@code exp} that is a whole number is sent as a number, anything else as a string. */
  private static final Pattern WHOLE_NUMBER = Pattern.compile("-?\\d{1,18}");

  private TokenRequestFactory() {
  }

  /**
   * Builds a token request.
   *
   * @param settings the token request settings, see {@link TokenRequestParameterModel#withDefaults}
   * @param tokenEndpoint the token endpoint of the OP
   * @param code the authorization code received from the OP (may be {@code null})
   * @param codeVerifier the PKCE code verifier of the authentication request (may be {@code null})
   * @param signingCredential the credential that signs a {@code private_key_jwt} client assertion - the signing key
   *     selected under "Key options" ({@code null} if that key is not available)
   * @param now the sending time
   * @return the token request
   * @throws TokenRequestException if the request cannot be built
   */
  @Nonnull
  public static SentTokenRequest create(@Nonnull final TokenRequestParameterModel settings,
      @Nonnull final String tokenEndpoint, @Nullable final String code, @Nullable final String codeVerifier,
      @Nullable final PkiCredential signingCredential, @Nonnull final Instant now) throws TokenRequestException {

    final String method = settings.getAuthMethod();
    if (!AUTH_METHODS.contains(method)) {
      throw new TokenRequestException("Unknown client authentication method '%s'".formatted(method));
    }

    final Map<String, String> headers = new LinkedHashMap<>();
    headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE + "; charset=UTF-8");
    headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
    if (CLIENT_SECRET_BASIC.equals(method)) {
      headers.put(HttpHeaders.AUTHORIZATION,
          basicAuthorization(value(settings.getClientId()), value(settings.getClientSecret())));
    }

    final Map<String, String> parameters = new LinkedHashMap<>();
    put(parameters, "grant_type", settings.getGrantType());
    putFilledIn(parameters, "code", settings.getCode(), code);
    put(parameters, "redirect_uri", settings.getRedirectUri());
    putFilledIn(parameters, "code_verifier", settings.getCodeVerifier(), codeVerifier);
    put(parameters, "client_id", settings.getClientId());
    put(parameters, "client_secret", settings.getClientSecret());
    put(parameters, "client_assertion_type", settings.getClientAssertionType());
    if (included(settings.getClientAssertion())) {
      final String typed = value(settings.getClientAssertion());
      if (!typed.isEmpty()) {
        parameters.put("client_assertion", typed);
      }
      else if (PRIVATE_KEY_JWT.equals(method) || CLIENT_SECRET_JWT.equals(method)) {
        parameters.put("client_assertion", clientAssertion(settings, method, signingCredential, now));
      }
      // Otherwise there is nothing to fill in, and the parameter is left out
    }

    return new SentTokenRequest("POST", tokenEndpoint, headers, parameters,
        Optional.ofNullable(parameters.get("client_assertion")).map(TokenRequestFactory::decode).orElse(null));
  }

  /**
   * Builds the client assertion from the claim rows of the settings (RFC 7523, section 3).
   *
   * @param settings the token request settings
   * @param method {@code private_key_jwt} or {@code client_secret_jwt}
   * @param signingCredential the credential signing a {@code private_key_jwt} assertion (may be {@code null})
   * @param now the sending time
   * @return the serialized client assertion
   * @throws TokenRequestException if the assertion cannot be built
   */
  @Nonnull
  static String clientAssertion(@Nonnull final TokenRequestParameterModel settings, @Nonnull final String method,
      @Nullable final PkiCredential signingCredential, @Nonnull final Instant now) throws TokenRequestException {

    final Map<String, Object> claims = new LinkedHashMap<>();
    if (included(settings.getAssertionIss())) {
      claims.put("iss", value(settings.getAssertionIss()));
    }
    if (included(settings.getAssertionSub())) {
      claims.put("sub", value(settings.getAssertionSub()));
    }
    if (included(settings.getAssertionAud())) {
      claims.put("aud", value(settings.getAssertionAud()));
    }
    if (included(settings.getAssertionIat())) {
      claims.put("iat", timeClaim(settings.getAssertionIat(), now.getEpochSecond()));
    }
    if (included(settings.getAssertionJti())) {
      final String jti = value(settings.getAssertionJti());
      claims.put("jti", jti.isEmpty() ? UUID.randomUUID().toString() : jti);
    }
    if (included(settings.getAssertionExp())) {
      claims.put("exp", timeClaim(settings.getAssertionExp(), now.getEpochSecond() + ASSERTION_LIFETIME_SECONDS));
    }

    try {
      final JWSHeader header;
      final JWSSigner signer;
      if (PRIVATE_KEY_JWT.equals(method)) {
        if (signingCredential == null) {
          throw new TokenRequestException("The client assertion could not be built: the signing key selected under"
              + " Key options is not available");
        }
        final JWK jwk = new JwkTransformerFunction().serializable().apply(signingCredential);
        header = new JWSHeader.Builder(JoseUtils.signingAlgorithm(signingCredential))
            .jwk(jwk.toPublicJWK())
            .keyID(jwk.getKeyID())
            .build();
        signer = JoseUtils.signer(signingCredential);
      }
      else {
        header = new JWSHeader(JWSAlgorithm.HS256);
        signer = new MACSigner(value(settings.getClientSecret()).getBytes(StandardCharsets.UTF_8));
      }
      final JWSObject assertion = new JWSObject(header, new Payload(claims));
      assertion.sign(signer);
      return assertion.serialize();
    }
    catch (final JOSEException | RuntimeException e) {
      throw new TokenRequestException("The client assertion could not be built: %s".formatted(
          Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName())), e);
    }
  }

  /**
   * Builds an {@code Authorization} header using the Basic scheme, from a client ID and a client secret (RFC 6749,
   * section 2.3.1). Both are encoded using the {@code application/x-www-form-urlencoded} encoding before they are
   * joined.
   *
   * @param clientId the client ID
   * @param clientSecret the client secret
   * @return the header value
   */
  @Nonnull
  static String basicAuthorization(@Nonnull final String clientId, @Nonnull final String clientSecret) {
    final String credentials = URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
        + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
    return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Decodes a client assertion for display. Nothing is verified.
   *
   * @param assertion the serialized client assertion
   * @return the header and claims, or why they could not be decoded
   */
  @Nonnull
  static SentTokenRequest.ClientAssertion decode(@Nonnull final String assertion) {
    try {
      final JWT jwt = JWTParser.parse(assertion);
      if (jwt instanceof EncryptedJWT) {
        return new SentTokenRequest.ClientAssertion(null, null, "the client assertion is an encrypted JWT");
      }
      final Payload payload = jwt instanceof final SignedJWT signed
          ? signed.getPayload()
          : ((PlainJWT) jwt).getPayload();
      final Map<String, Object> claims = payload.toJSONObject();
      if (claims == null) {
        return new SentTokenRequest.ClientAssertion(null, null, "the payload is not a JSON object");
      }
      return new SentTokenRequest.ClientAssertion(jwt.getHeader().toJSONObject(), claims, null);
    }
    catch (final ParseException | RuntimeException e) {
      return new SentTokenRequest.ClientAssertion(null, null,
          Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName()));
    }
  }

  private static Object timeClaim(@Nonnull final ModelParameter row, final long filledIn) {
    final String typed = value(row);
    if (typed.isEmpty()) {
      return filledIn;
    }
    return WHOLE_NUMBER.matcher(typed).matches() ? (Object) Long.parseLong(typed) : typed;
  }

  private static void put(@Nonnull final Map<String, String> parameters, @Nonnull final String name,
      @Nullable final ModelParameter row) {
    if (included(row)) {
      parameters.put(name, value(row));
    }
  }

  private static void putFilledIn(@Nonnull final Map<String, String> parameters, @Nonnull final String name,
      @Nullable final ModelParameter row, @Nullable final String filledIn) {
    if (!included(row)) {
      return;
    }
    final String typed = value(row);
    if (!typed.isEmpty()) {
      parameters.put(name, typed);
    }
    else if (filledIn != null) {
      parameters.put(name, filledIn);
    }
  }

  private static boolean included(@Nullable final ModelParameter row) {
    return row != null && Boolean.TRUE.equals(row.getValuePresent());
  }

  @Nonnull
  private static String value(@Nullable final ModelParameter row) {
    return Optional.ofNullable(row).map(ModelParameter::getValue).orElse("");
  }
}
