package se.swedenconnect.testclient.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Pair;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import lombok.AllArgsConstructor;
import net.minidev.json.JSONObject;
import se.swedenconnect.testclient.oidc.RequestObjectFactory;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

@AllArgsConstructor
public class AuthorizationParameterResolver {

  private final OIDCAuthnRequestParameterModel model;
  private final Boolean forRequestBody;
  private final BiConsumer<String, Object> saveFunction;
  private final Function<String, Object> loadFunction;

  private <T> Optional<T> getServerGeneratedValue(
      final ModelParameter parameter,
      final Supplier<T> defaultValueSupplier,
      final Function<String, T> transformFunction) {
    if (!parameter.getValuePresent()) {
      return Optional.empty();
    }
    if (parameter.getRequestBody() == this.forRequestBody) {
      if (Objects.isNull(parameter.getValue()) || parameter.getValue().isBlank()) {
        return Optional.of(defaultValueSupplier.get());
      }
      return Optional.of(transformFunction.apply(parameter.getValue()));
    }
    return Optional.empty();
  }

  private <T> Optional<T> getValue(final ModelParameter parameter, final Function<String, T> transformFunction) {
    if (parameter.getValuePresent() && !this.forRequestBody) {
      return Optional.of(transformFunction.apply(parameter.getValue()));
    }
    if (parameter.getRequestBody() && this.forRequestBody) {
      return Optional.of(transformFunction.apply(parameter.getValue()));
    }
    return Optional.empty();
  }

  public Optional<State> getState() {
    return this.getServerGeneratedValue(this.model.getAdvanced().getState(), State::new, State::new);
  }

  public Optional<Nonce> getNonce() {
    return this.getServerGeneratedValue(this.model.getAdvanced().getNonce(), Nonce::new, Nonce::new);
  }

  public Optional<URI> getRedirectionURI() {
    return this.getValue(this.model.getRedirectUri(), URI::create);
  }

  public Optional<ClientID> getClientId() {
    return this.getValue(this.model.getClientId(), ClientID::new);
  }

  public Optional<Scope> getScope() {
    final Optional<Scope> scope = this.getValue(this.model.getScope(), scopeString -> new Scope(scopeString.split(" ")));
    if (scope.isEmpty() && !this.forRequestBody) {
      //Scope needs to be "openid" for request if other scopes are specified in request object
      return Optional.of(new Scope("openid"));
    }
    return scope;
  }

  public Optional<OidcMessageParameterModel> getUserMessage() {
    return Optional.ofNullable(this.model.getUserMessage()).flatMap(um -> {
      if (um.getValuePresent() && !forRequestBody) {
        return Optional.of(um);
      }
      if (um.getRequestBody() && forRequestBody) {
        return Optional.of(um);
      }
      return Optional.empty();
    });
  }

  public Optional<SignatureParameterModel> getSignMessage() {
    return Optional.ofNullable(this.model.getSignMessage()).flatMap(sm -> {
      if (sm.getValuePresent() && !forRequestBody) {
        return Optional.of(sm);
      }
      if (sm.getRequestBody() && forRequestBody) {
        return Optional.of(sm);
      }
      return Optional.empty();
    });
  }

  public Optional<ResponseType> getResponseType() {
    return this.getValue(this.model.getAdvanced().getResponseType(), rt -> {
      return new ResponseType(rt.split(" "));
    });
  }

  public Optional<List<ACR>> getAcrValues() {
    return this.getValue(this.model.getAcrValues(), value -> Arrays.stream(value.split("\\s+")).map(ACR::new).toList());
  }

  public Optional<Prompt> getPrompt() {
    return this.getValue(this.model.getAdvanced().getPrompt(), Prompt::new);
  }

  public Optional<String> getLoginHint() {
    return this.getValue(this.model.getAdvanced().getLoginHint(), v -> v);
  }

  public Optional<Pair<CodeChallengeMethod, CodeVerifier>> getCodeChallenge() {
    final Optional<Pair<CodeChallengeMethod, CodeVerifier>> codeVerifier = Optional.ofNullable((Pair<CodeChallengeMethod, CodeVerifier>) this.loadFunction.apply("code_verifier"));
    if (codeVerifier.isPresent()) {
      return codeVerifier;
    }
    final Optional<CodeChallengeMethod> method = this.getValue(this.model.getAdvanced().getCodeChallengeMethod(),
        CodeChallengeMethod::new);
    final Optional<CodeVerifier> value = this.getServerGeneratedValue(this.model.getAdvanced().getCodeChallenge(),
        CodeVerifier::new,
        CodeVerifier::new
    );

    if (method.isPresent() && value.isPresent()) {
      final Pair<CodeChallengeMethod, CodeVerifier> verifier = Pair.of(method.get(), value.get());
      saveFunction.accept("code_verifier", verifier);
      return Optional.of(verifier);
    }
    return Optional.empty();
  }

  public Optional<JWT> requestBody(final Function<String, JWK> kidToJwtFunction) throws JOSEException, ParseException {
    final JWTClaimsSet claims = RequestObjectFactory.getClaims(
        model,
        this.toRequestObjectResolver()
    );
    if (claims.toJSONObject().size() <= 2) {
      return Optional.empty();
    }
    saveFunction.accept("jwt_claims", claims);
    if (model.getRequestObject().getSignRequest()) {
      final SignedJWT signedJWT = RequestObjectFactory.getSignedJWT(model, kidToJwtFunction, claims);
      saveFunction.accept("signed_jwt", signedJWT);
      if (model.getRequestObject().getEncryptRequest()) {
        final EncryptedJWT encryptedJWT = RequestObjectFactory.getEncryptedSignedJWT(model, kidToJwtFunction, signedJWT);
        saveFunction.accept("encrypted_signed_jwt", encryptedJWT);
        return Optional.of(encryptedJWT);
      }
      return Optional.of(signedJWT);
    }
    if (model.getRequestObject().getEncryptRequest()) {
      final EncryptedJWT encryptedPlainJwt = RequestObjectFactory.getEncryptedPlainJwt(model, kidToJwtFunction, claims);
      saveFunction.accept("encrypted_plain_jwt", encryptedPlainJwt);
      return Optional.of(encryptedPlainJwt);
    }

    final PlainJWT jwt = new PlainJWT(claims);
    saveFunction.accept("plain_jwt", claims);
    return Optional.of(jwt);
  }

  public Optional<OIDCClaimsRequest> getClaimRequest() throws ParseException {
    if (Objects.isNull(model.getClaims()) || model.getClaims().isEmpty()) {
      return Optional.empty();
    }
    if (this.forRequestBody == model.getClaimInRequestBody()) {
      return Optional.of(OIDCClaimsRequest.parse(new JSONObject(this.model.getClaims())));
    }
    return Optional.empty();
  }

  public AuthorizationParameterResolver toRequestObjectResolver() {
    return new AuthorizationParameterResolver(this.model, true, this.saveFunction, this.loadFunction);
  }
}
