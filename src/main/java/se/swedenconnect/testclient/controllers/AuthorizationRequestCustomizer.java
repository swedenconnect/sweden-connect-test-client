package se.swedenconnect.testclient.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.shaded.gson.ExclusionStrategy;
import com.nimbusds.jose.shaded.gson.FieldAttributes;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Function;

public class AuthorizationRequestCustomizer {

  public static final Gson GSON = new GsonBuilder()
      .registerTypeAdapter(OidcMessageParameterModel.class, new OidcMessageSerializer())
      .addSerializationExclusionStrategy(new ExclusionStrategy() {
        @Override
        public boolean shouldSkipField(final FieldAttributes fieldAttributes) {
          return "requestBody".equals(fieldAttributes.getName()) || "valuePresent".equals(fieldAttributes.getName());
        }

        @Override
        public boolean shouldSkipClass(final Class<?> aClass) {
          return false;
        }
      })
      .create();

  public static AuthenticationRequest.Builder customize(
      final AuthenticationRequest.Builder builder,
      final Function<String, JWK> jwkFunction,
      final AuthorizationParameterResolver resolver
  ) throws JOSEException, ParseException {

    resolver.getUserMessage()
        .ifPresent(um ->
            builder.customParameter("https://id.oidc.se/param/userMessage", GSON.toJson(um))
        );

    resolver.getSignMessage()
        .ifPresent(sig -> {
          if(sig.getB64Encode()) {
            final String tbsData = Base64.getEncoder().encodeToString(sig.getTbsData().getBytes(StandardCharsets.UTF_8));
            sig.setTbsData(tbsData);
          } else {
            sig.setTbsData(sig.getTbsData());
          }
          builder.customParameter("https://id.oidc.se/param/signRequest", GSON.toJson(sig));
        });

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
