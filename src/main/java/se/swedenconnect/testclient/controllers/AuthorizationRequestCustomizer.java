package se.swedenconnect.testclient.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import java.util.function.Function;

public class AuthorizationRequestCustomizer {
  public static AuthenticationRequest.Builder customize(
      final AuthenticationRequest.Builder builder,
      final Function<String, JWK> jwkFunction,
      final AuthorizationParameterResolver resolver
  ) throws JOSEException, ParseException {


    resolver.getNonce().ifPresent(builder::nonce);
    resolver.getState().ifPresent(builder::state);
    resolver.getRedirectionURI().ifPresent(builder::redirectionURI);
    resolver.requestBody(jwkFunction).ifPresent(builder::requestObject);
    resolver.getAcrValues().ifPresent(builder::acrValues);
    resolver.getPrompt().ifPresent(builder::prompt);
    resolver.getScope().ifPresent(builder::scope);
    resolver.getResponseType().ifPresent(builder::responseType);
    resolver.getLoginHint().ifPresent(builder::loginHint);
    resolver.getCodeChallenge().ifPresent(cc -> {
      builder.codeChallenge(cc.getRight(), cc.getLeft());
    });
    resolver.getClaimRequest().ifPresent(builder::claims);
    return builder;
  }
}
