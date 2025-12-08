package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import se.swedenconnect.testclient.controllers.AuthorizationParameterResolver;
import se.swedenconnect.testclient.controllers.OIDCAuthnRequestParameterModel;

import java.util.function.Function;
import java.util.stream.Collectors;

public class RequestObjectFactory {
  public static EncryptedJWT getEncryptedSignedJWT(final OIDCAuthnRequestParameterModel model,
                                                   final Function<String, JWK> getJwkFromKid, final SignedJWT signedJWT) throws JOSEException {
    final JWK encKey = getJwkFromKid.apply(model.getKeys().getEncKey());
    final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT")
        .keyID(encKey.getKeyID())
        .build();
    final EncryptedJWT encryptedJWT = new EncryptedJWT(header, new JWTClaimsSet.Builder().claim("payload",
        signedJWT.serialize()).build());
    encryptedJWT.encrypt(new RSAEncrypter(encKey.toRSAKey().toRSAPublicKey()));
    return encryptedJWT;
  }

  public static EncryptedJWT getEncryptedPlainJwt(final OIDCAuthnRequestParameterModel model,
                                                   final Function<String, JWK> getJwkFromKid,
                                                   final JWTClaimsSet jwtClaimsSet) throws JOSEException {
    final JWK encKey = getJwkFromKid.apply(model.getKeys().getEncKey());
    final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
        .contentType("JWT")
        .keyID(encKey.getKeyID())
        .build();
    final EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
    encryptedJWT.encrypt(new RSAEncrypter(encKey.toRSAKey()));
    return encryptedJWT;
  }

  public static JWTClaimsSet getClaims(
      final OIDCAuthnRequestParameterModel model,
      final AuthorizationParameterResolver resolver
  ) throws ParseException {
    final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
    if (model.getRequestObject().getAudience().getRequestBody()) {
      builder.audience(model.getRequestObject().getAudience().getValue());
    }
    if (model.getRequestObject().getIssuer().getRequestBody()) {
      builder.issuer(model.getRequestObject().getIssuer().getValue());
    }
    resolver.getNonce().ifPresent(nonce -> builder.claim("nonce", nonce.getValue()));
    resolver.getState().ifPresent(state -> builder.claim("state", state.getValue()));
    resolver.getRedirectionURI().ifPresent(uri -> builder.claim("redirection_uri", uri.toASCIIString()));
    resolver.getAcrValues().ifPresent(acr -> builder.claim("acr_values",
        acr.stream().map(Identifier::getValue).collect(Collectors.joining(" "))));
    resolver.getPrompt().ifPresent(prompt -> builder.claim("prompt", prompt.toStringList()));
    resolver.getScope().ifPresent(scope -> builder.claim("scope", scope.toStringList()));
    resolver.getResponseType().ifPresent(responseType -> builder.claim("response_type", responseType.toString()));
    resolver.getLoginHint().ifPresent(loginHint -> builder.claim("login_hint", loginHint));
    if (resolver.getCodeChallenge().isPresent()) {
      final Pair<CodeChallengeMethod, CodeVerifier> codeChallenge = resolver.getCodeChallenge().get();
      builder.claim("code_challenge", codeChallenge.getRight().getValue());
      builder.claim("code_challenge_method", codeChallenge.getLeft());
    }
    resolver.getClaimRequest().ifPresent(oidcClaimsRequest -> builder.claim("claims", oidcClaimsRequest.toJSONObject()));

    return builder.build();
  }

  public static SignedJWT getSignedJWT(final OIDCAuthnRequestParameterModel model,
                                       final Function<String, JWK> getJwkFromKid,
                                       final JWTClaimsSet claims) throws JOSEException {
    final JWK signKey = getJwkFromKid.apply(model.getKeys().getSignKey());
    final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signKey.getKeyID()).build();
    final SignedJWT signedJWT = new SignedJWT(header, claims);
    signedJWT.sign(new RSASSASigner(signKey.toRSAKey()));
    return signedJWT;
  }
}
