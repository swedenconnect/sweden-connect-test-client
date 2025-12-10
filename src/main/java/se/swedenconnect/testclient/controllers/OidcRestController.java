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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * REST Controller for OpenID Connect support.
 *
 * @author Martin Lindström
 */
@RestController
@RequestMapping("/oidc")
@ConditionalOnProperty(value = "testclient.oidc.enabled", havingValue = "true")
public class OidcRestController {
  /**
   * OIDC RP:s.
   */
  private final List<OidcRp> oidcRps;
  private final List<OidcOp> oidcOps;
  private final HttpSession httpSession;
  private final OIDCOPMetadataFetcher fetcher;
  private final CredentialBundles credentialBundles;

  public OidcRestController(
      @Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> oidcRps,
      @Qualifier("testclient.oidc.OpList") @Nonnull final List<OidcOp> oidcOps,
      final HttpSession httpSession,
      final OIDCOPMetadataFetcher fetcher,
      final CredentialBundles credentialBundles) {
    this.oidcRps = oidcRps;
    this.oidcOps = oidcOps;
    this.httpSession = httpSession;
    this.fetcher = fetcher;
    this.credentialBundles = credentialBundles;
  }

  @GetMapping(value = "/session/info")
  public Map<String, Object> getSessionInfo() {
    return Map.of();
  }

  @GetMapping(value = "/rp/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<OidcRpInfoModel> getOidcRpInfo() {
    return this.oidcRps.stream()
        .map(rp -> new OidcRpInfoModel(rp.getEntityId(), rp.getDescription(),
            rp.getMetadata().toJSONObject(true).toJSONString()))
        .toList();
  }

  @PostMapping(value = "/authn/verify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public Object verifyOidcResponse(
      @Nonnull @RequestBody final Map<String, Object> response) {
    return response.get("response_data");
  }

  @GetMapping(value = "/rp/metadata")
  public JSONObject getMetadata(@RequestParam("rp") final String entityId) {
    return this.oidcRps.stream().findFirst().filter(rp -> rp.getEntityId().equals(entityId)).orElseThrow(() -> {
      return new RuntimeException("Failed to find metadata for %s".formatted(entityId));
    }).getMetadata().toJSONObject(true);
  }

  @GetMapping(value = "/op/metadata")
  public JSONObject getOpMetadata(@RequestParam("op") final String entityId) {
    final OidcOp selectedOP = this.oidcOps.stream().findFirst().filter(rp -> rp.getEntityId().equals(entityId)).orElseThrow(() -> {
      return new RuntimeException("Failed to find metadata for %s".formatted(entityId));
    });
    return this.fetcher.getOPMetadata(selectedOP);
  }

  @GetMapping(value = "/authn/info")
  public OIDCInitAuthnModel initInfo() {
    final List<OpenIdRelyingPartyModel> relyingParties = this.oidcRps.stream().map(rp -> new OpenIdRelyingPartyModel(rp.getEntityId(), rp.getMetadata().getName(),
        rp.getDescription(), "/oidc/rp/metadata?rp=" + URLEncoder.encode(rp.getEntityId(), Charset.defaultCharset()))).toList();

    final List<OpenIdProviderModel> providers = this.oidcOps.stream().map(op -> new OpenIdProviderModel(
            op.getEntityId(),
            "display",
            "description",
            "https://metadata.test"))
        .toList();

    return new OIDCInitAuthnModel(relyingParties, providers);
  }

  @GetMapping(value = "/authn/template")
  public OIDCAuthnRequestParameterModel template(
      @RequestParam("rp") final String rp,
      @RequestParam("op") final String op,
      final HttpSession session
  ) {
    session.invalidate();
    final OidcRp selectedRp =
        this.oidcRps.stream().filter(relyingParty -> rp.equals(relyingParty.getEntityId())).findFirst()
            .orElseThrow(() -> new RuntimeException("No such relying party found"));

    final OidcOp selectedOp =
        this.oidcOps.stream().filter(openIdProvider -> op.equals(openIdProvider.getEntityId())).findFirst()
            .orElseThrow(() -> new RuntimeException("No such OpenID Provider found"));

    final JSONObject opMetadata = this.fetcher.getOPMetadata(selectedOp);
    final JWKSet opJWKS = this.fetcher.getOPJWKS(opMetadata.getAsString("jwks_uri"));
    final JWK opEncKey = opJWKS.getKeys()
        .stream()
        .filter(jwk -> {
          return jwk.getKeyUse().getValue().equals("enc");
        })
        .findFirst()
        .get();
    final List<KeyModel> encryptionKeys = opJWKS.getKeys()
        .stream()
        .map(jwk -> {
          final KeyModel.KeyModelBuilder builder = KeyModel.builder()
              .alg(Optional.ofNullable(jwk.getKeyType()).map(KeyType::getValue).orElse("?"))
              .kid(jwk.getKeyID())
              .typ("");
          if (opEncKey.getKeyID().equals(jwk.getKeyID())) {
            builder.description("[Registered Key]");
          }
          return builder.build();
        })
        .toList();
    final PkiCredential credentialForSigning = selectedRp.getCredentials().getCredentialForSigning();
    final JWK signKey = new JwkTransformerFunction()
        .serializable()
        .apply(credentialForSigning);

    final List<KeyModel> signKeys = credentialBundles.getRegisteredCredentials()
        .stream()
        .map(credentialBundles::getCredential)
        .map(credential -> new JwkTransformerFunction()
            .serializable()
            .apply(credential))
        .map(jwk -> {
          final KeyModel.KeyModelBuilder builder = KeyModel.builder()
              .alg(Optional.ofNullable(jwk.getKeyType()).map(KeyType::getValue).orElse("?"))
              .kid(jwk.getKeyID())
              .typ("");
          if (signKey.getKeyID().equals(jwk.getKeyID())) {
            builder.description("[Registered Key]");
          }
          return builder.build();

        })
        .toList();


    return OIDCAuthnRequestParameterModel.builder()
        .op(op)
        .rp(rp)
        .scope(new ModelParameter("openid", false, true))
        .redirectUri(new ModelParameter(selectedRp.getMetadata().getRedirectionURI().toASCIIString(), false, true))
        .clientId(new ModelParameter(selectedRp.getEntityId(), false, true))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequestBody(false)
        .advanced(AdvancedOptionsParamterModel.builder()
            .state(ModelParameter.builder().valuePresent(true).requestBody(false).build())
            .nonce(ModelParameter.builder().valuePresent(true).requestBody(false).build())
            .prompt(ModelParameter.builder().valuePresent(false).requestBody(false).build())
            .loginHint(ModelParameter.builder().value("value").valuePresent(false).requestBody(false).build())
            .responseType(ModelParameter.builder().value("code").valuePresent(true).requestBody(false).build())
            .codeChallenge(ModelParameter.builder().valuePresent(false).requestBody(false).build())
            .codeChallengeMethod(ModelParameter.builder().value("plain").valuePresent(false).requestBody(false).build())
            .moduleEnabled(false).build())
        .keys(KeyOptionsParameterModel.builder()
            .signKeys(signKeys)
            .encKeys(encryptionKeys)
            .encKey(opEncKey.getKeyID())
            .signKey(signKey.getKeyID())
            .moduleEnabled(true).build())
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter("issuer", true, true))
            .audience(new ModelParameter("audience", true, true))
            .signRequest(false)
            .encryptRequest(false)
            .moduleEnabled(false).build())
        .build();
  }

  @PostMapping(value = "/authn/generate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public OIDCAuthnRequestModel generateAuthnRequest(
      @Nonnull @RequestBody final OIDCAuthnRequestParameterModel model
  ) throws JOSEException, ParseException {
    try {
      final OidcRp selectedRp =
          this.oidcRps.stream().filter(rp -> model.getRp().equals(rp.getEntityId())).findFirst()
              .orElseThrow(() -> new RuntimeException("No such relying party found"));

      final OidcOp selectedOp = this.oidcOps.stream().filter(op -> op.getEntityId().equals(model.getOp())).findFirst()
          .orElseThrow(() -> new RuntimeException("No such OpenID Provider found"));

      final JSONObject opMetadata = this.fetcher.getOPMetadata(selectedOp);
      final JWKSet opJWKS = this.fetcher.getOPJWKS(opMetadata.getAsString("jwks_uri"));

      final AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
          new ResponseType("code"),
          new Scope("openid"),
          new ClientID(model.getClientId().getValue()),
          URI.create(model.getRedirectUri().getValue()))
          .endpointURI(URI.create(selectedOp.getAuthorizationEndpoint()));

      final AuthenticationRequest authRequest = AuthorizationRequestCustomizer.customize(
          builder,
          kidtoJwkFunction(opJWKS),
          new AuthorizationParameterResolver(model,
              false,
              httpSession::setAttribute,
              httpSession::getAttribute
          )
      ).build();

      httpSession.setAttribute("auth_request", authRequest);
      httpSession.setAttribute("selected_op", selectedOp);
      httpSession.setAttribute("selected_rp", selectedRp);

      return OIDCAuthnRequestModel.builder()
          .method("GET")
          .url(authRequest.toHTTPRequest().getURI().toASCIIString())
          .build();
    } catch (final Exception e) {
      httpSession.invalidate();
      throw e;
    }
  }

  private Function<String, JWK> kidtoJwkFunction(final JWKSet opJWKS) {
    return (s) -> {
      return Optional.ofNullable(opJWKS.getKeyByKeyId(s))
          .or(() -> {
            final JWKSet signKeys = new JWKSet(credentialBundles.getRegisteredCredentials()
                .stream()
                .map(credentialBundles::getCredential)
                .map(credential -> new JwkTransformerFunction()
                    .serializable()
                    .apply(credential)).toList());
            return Optional.ofNullable(signKeys
                .getKeyByKeyId(s));
          }).orElseThrow(() -> {
            return new RuntimeException("Failed to determine key for kid %s".formatted(s));
          });
    };
  }

  @AllArgsConstructor
  @NoArgsConstructor
  @Getter
  @Setter
  @Builder
  public static class OIDCAuthnRequestModel {
    private String method;
    private String url;
  }

  @AllArgsConstructor
  @NoArgsConstructor
  @Getter
  @Setter
  public static class OIDCInitAuthnModel {
    private List<OpenIdRelyingPartyModel> rps;
    private List<OpenIdProviderModel> ops;
  }

  @AllArgsConstructor
  @NoArgsConstructor
  @Getter
  @Setter
  public static class OpenIdProviderModel {
    @JsonProperty("entity_id")
    private String entityID;

    @JsonProperty("display_name")
    private String displayName;

    private String description;

    private String metadataUrl;
  }

  @AllArgsConstructor
  @NoArgsConstructor
  @Getter
  @Setter
  public static class OpenIdRelyingPartyModel {
    @JsonProperty("entity_id")
    private String entityID;

    @JsonProperty("display_name")
    private String displayName;

    private String description;

    @JsonProperty("metadata_url")
    private String metadataUrl;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OidcRpInfoModel {
    @JsonProperty("entity-id")
    private String entityId;

    private String description;
    @JsonProperty("metadata_url")
    private String metadataJson;
  }
}
