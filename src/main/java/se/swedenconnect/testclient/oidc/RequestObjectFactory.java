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
package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import jakarta.annotation.Nonnull;
import se.swedenconnect.testclient.controllers.AuthorizationParameterResolver;
import se.swedenconnect.testclient.controllers.OIDCAuthnRequestParameterModel;
import se.swedenconnect.testclient.controllers.OidcMessageSerializer;
import se.swedenconnect.testclient.controllers.SignatureParameterModel;
import se.swedenconnect.testclient.utils.JoseUtils;

import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Creates the JWT:s of an OIDC authentication request - the request object and the sign request that is sent in the
 * request URL. Each may be signed or unsecured, and optionally encrypted.
 * <p>
 * An encrypted JWT is always a nested JWT (RFC 7519, sections 2 and 7.2): the plaintext of the encryption is the
 * serialized signed or unsecured JWT, and the encryption header has {@code cty: JWT}.
 * </p>
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
public class RequestObjectFactory {

  /**
   * Encrypts a signed or unsecured JWT for the encryption key of the key options.
   *
   * @param model the request parameter model
   * @param getJwkFromKid function giving the key for a key ID
   * @param jwt the JWT to encrypt
   * @return the encrypted, nested, JWT
   * @throws JOSEException for encryption errors
   */
  @Nonnull
  public static EncryptedJWT getEncryptedJWT(@Nonnull final OIDCAuthnRequestParameterModel model,
      @Nonnull final Function<String, JWK> getJwkFromKid, @Nonnull final JWT jwt) throws JOSEException {
    return encrypt(jwt, getJwkFromKid.apply(model.getKeys().getEncKey()));
  }

  /**
   * Encrypts a signed or unsecured JWT. The result is a nested JWT whose plaintext is the serialized JWT.
   *
   * @param jwt the JWT to encrypt
   * @param encKey the key to encrypt for
   * @return the encrypted JWT
   * @throws JOSEException for encryption errors
   */
  @Nonnull
  public static EncryptedJWT encrypt(@Nonnull final JWT jwt, @Nonnull final JWK encKey) throws JOSEException {
    final JWEHeader header = new JWEHeader.Builder(JoseUtils.keyEncryptionAlgorithm(encKey), EncryptionMethod.A256GCM)
        .contentType("JWT")
        .keyID(encKey.getKeyID())
        .build();
    final JWEObject jwe = new JWEObject(header, new Payload(jwt.serialize()));
    jwe.encrypt(JoseUtils.encrypter(encKey));
    try {
      return EncryptedJWT.parse(jwe.serialize());
    }
    catch (final java.text.ParseException e) {
      throw new JOSEException("Failed to create encrypted JWT", e);
    }
  }

  /**
   * Signs claims with a key.
   *
   * @param claims the claims
   * @param signKey the key to sign with
   * @return the signed JWT
   * @throws JOSEException for signing errors
   */
  @Nonnull
  public static SignedJWT sign(@Nonnull final JWTClaimsSet claims, @Nonnull final JWK signKey) throws JOSEException {
    final JWSHeader header =
        new JWSHeader.Builder(JoseUtils.signingAlgorithm(signKey)).keyID(signKey.getKeyID()).build();
    final SignedJWT signedJWT = new SignedJWT(header, claims);
    signedJWT.sign(JoseUtils.signer(signKey));
    return signedJWT;
  }

  /**
   * Gets the JWT carrying the sign request in the request URL. Its claims set is the sign request object. Depending on
   * the settings of the sign request it is signed with its selected key or unsecured, and optionally encrypted for the
   * encryption key of the key options.
   *
   * @param model the request parameter model
   * @param getJwkFromKid function giving the key for a key ID
   * @return the JWT
   * @throws JOSEException for signing or encryption errors
   * @throws ParseException if the sign request is not a valid claims set
   */
  @Nonnull
  public static JWT getSignRequestJWT(@Nonnull final OIDCAuthnRequestParameterModel model,
      @Nonnull final Function<String, JWK> getJwkFromKid) throws JOSEException, ParseException {
    final SignatureParameterModel signRequest = model.getSignMessage();
    final JWTClaimsSet claims;
    try {
      claims = JWTClaimsSet.parse(OidcMessageSerializer.toSignRequest(signRequest));
    }
    catch (final java.text.ParseException e) {
      throw new ParseException("Invalid sign request: " + e.getMessage(), e);
    }
    final JWT jwt = Boolean.FALSE.equals(signRequest.getSignJwt())
        ? new PlainJWT(claims)
        : sign(claims, getJwkFromKid.apply(signRequest.getSignKey()));
    return Boolean.TRUE.equals(signRequest.getEncryptJwt())
        ? getEncryptedJWT(model, getJwkFromKid, jwt)
        : jwt;
  }

  /**
   * Gets the claims of the request object.
   *
   * @param model the request parameter model
   * @param resolver the resolver for the request object
   * @return the claims
   * @throws ParseException for invalid claims requests
   */
  @Nonnull
  public static JWTClaimsSet getClaims(
      @Nonnull final OIDCAuthnRequestParameterModel model,
      @Nonnull final AuthorizationParameterResolver resolver
  ) throws ParseException {
    final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    if (model.getRequestObject().getAudience().getRequestBody()) {
      builder.audience(model.getRequestObject().getAudience().getValue());
    }
    if (model.getRequestObject().getIssuer().getRequestBody()) {
      builder.issuer(model.getRequestObject().getIssuer().getValue());
    }
    resolver.getUserMessage().ifPresent(um ->
        builder.claim(OidcMessageSerializer.USER_MESSAGE, OidcMessageSerializer.toUserMessage(um)));
    resolver.getSignMessage().ifPresent(sig ->
        builder.claim(OidcMessageSerializer.SIGN_REQUEST, OidcMessageSerializer.toSignRequest(sig)));

    resolver.getClientId().ifPresent(clientId -> builder.claim("client_id", clientId.getValue()));
    resolver.getNonce().ifPresent(nonce -> builder.claim("nonce", nonce.getValue()));
    resolver.getState().ifPresent(state -> builder.claim("state", state.getValue()));
    resolver.getRedirectionURI().ifPresent(uri -> builder.claim("redirect_uri", uri.toASCIIString()));
    resolver.getAcrValues().ifPresent(acr -> builder.claim("acr_values",
        acr.stream().map(Identifier::getValue).collect(Collectors.joining(" "))));
    resolver.getPrompt().ifPresent(prompt -> builder.claim("prompt", prompt));
    resolver.getScope().ifPresent(scope -> builder.claim("scope", String.join(" ", scope.toStringList())));
    resolver.getResponseType().ifPresent(responseType -> builder.claim("response_type", responseType.toString()));
    resolver.getLoginHint().ifPresent(loginHint -> builder.claim("login_hint", loginHint));
    resolver.getCodeChallenge().ifPresent(codeChallenge -> {
      builder.claim("code_challenge",
          CodeChallenge.compute(codeChallenge.getLeft(), codeChallenge.getRight()).getValue());
      builder.claim("code_challenge_method", codeChallenge.getLeft().getValue());
    });
    resolver.getClaimRequest()
        .ifPresent(oidcClaimsRequest -> builder.claim("claims", oidcClaimsRequest.toJSONObject()));

    return builder.build();
  }

  /**
   * Signs the request object claims with the signing key of the key options.
   *
   * @param model the request parameter model
   * @param getJwkFromKid function giving the key for a key ID
   * @param claims the request object claims
   * @return the signed JWT
   * @throws JOSEException for signing errors
   */
  @Nonnull
  public static SignedJWT getSignedJWT(@Nonnull final OIDCAuthnRequestParameterModel model,
      @Nonnull final Function<String, JWK> getJwkFromKid, @Nonnull final JWTClaimsSet claims) throws JOSEException {
    return sign(claims, getJwkFromKid.apply(model.getKeys().getSignKey()));
  }

  // Hidden constructor
  private RequestObjectFactory() {
  }
}
