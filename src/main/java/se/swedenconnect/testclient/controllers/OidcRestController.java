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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.oidc.federation.OidfClient;
import se.swedenconnect.testclient.utils.UrlBuilderBean;

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
@Slf4j
@RestController
@RequestMapping("/oidc")
@ConditionalOnProperty(value = "testclient.oidc.enabled", havingValue = "true")
public class OidcRestController {
  /**
   * OIDC RP:s.
   */
  private final List<OidcRp> oidcRps;
  private final OidcOpRegistry opRegistry;
  private final HttpSession httpSession;
  private final OIDCOPMetadataFetcher fetcher;
  private final CredentialBundles credentialBundles;
  private final UrlBuilderBean urlBuilderBean;
  private final RestClient client;
  private final UserInfoCaller userInfoCaller;

  public OidcRestController(
      @Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> oidcRps,
      @Nonnull final OidcOpRegistry opRegistry,
      final HttpSession httpSession,
      final OIDCOPMetadataFetcher fetcher,
      final CredentialBundles credentialBundles,
      @Nonnull final UrlBuilderBean urlBuilderBean,
      final RestClient client) {
    this.oidcRps = oidcRps;
    this.opRegistry = opRegistry;
    this.httpSession = httpSession;
    this.fetcher = fetcher;
    this.credentialBundles = credentialBundles;
    this.urlBuilderBean = urlBuilderBean;
    this.client = client;
    this.userInfoCaller = new UserInfoCaller(client);
  }

  @GetMapping(value = "/session/info")
  public Map<String, Object> getSessionInfo() {
    return Map.of();
  }

  @GetMapping(value = "/rp/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<OidcRpInfoModel> getOidcRpInfo() {
    return this.oidcRps.stream()
        .map(rp -> new OidcRpInfoModel(rp.getEntityId(), rp.getDescription(),
            this.urlBuilderBean.buildUrl(
                "/oidc/rp/metadata?rp=" + URLEncoder.encode(rp.getEntityId(), Charset.defaultCharset())),
            rp.isUseJwksUrl() ? rp.getJwksUri() : null, entityConfigurationUrl(rp)))
        .toList();
  }

  @GetMapping(value = "/op/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<OidcOpInfoModel> getOidcOpInfo() {
    return this.opRegistry.getOps().stream()
        .map(op -> new OidcOpInfoModel(op.getEntityId(), op.getDisplayName(), op.getDescription(),
            op.getMetadataEndpoint(),
            Optional.ofNullable(op.getSource()).orElse(OidcOp.Source.STATIC).name().toLowerCase(),
            op.getTrustAnchor()))
        .toList();
  }

  /**
   * Sends a UserInfo request for the latest authentication ("Send UserInfo Request" on the authentication result). The
   * request is sent to the UserInfo endpoint of the OP selected for the authentication, and the response is read using
   * the keys of the RP selected for the authentication.
   * <p>
   * The call itself is always reported in the result - error statuses and network errors included. If the
   * authentication is still in the session, the result also holds the UserInfo parts of the authentication result,
   * evaluated against the new call.
   * </p>
   *
   * @param request the access token and HTTP method to use
   * @return the call and its evaluation
   */
  @PostMapping(value = "/authn/userinfo", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public UserInfoCallModel sendUserInfoRequest(@Nonnull @RequestBody final UserInfoRequestModel request) {
    final AuthenticationRequest authRequest = (AuthenticationRequest) this.httpSession.getAttribute("auth_request");
    final OidcOp selectedOp = (OidcOp) this.httpSession.getAttribute("selected_op");
    final OidcRp selectedRp = (OidcRp) this.httpSession.getAttribute("selected_rp");
    if (authRequest == null || selectedOp == null || selectedRp == null) {
      log.info("UserInfo request rejected: there is no OIDC authentication in the session");
      return new UserInfoCallModel(UserInfoExchange.builder()
          .error("There is no OIDC authentication in the session - restart the authentication")
          .build(), null);
    }
    final HttpMethod method = Optional.ofNullable(request.getMethod())
        .filter(m -> !m.isBlank())
        .map(m -> HttpMethod.valueOf(m.trim().toUpperCase()))
        .orElse(HttpMethod.GET);

    final UserInfoExchange exchange =
        this.userInfoCaller.call(selectedOp.getUserInfoEndpoint(), request.getAccessToken(), method, selectedRp);

    @SuppressWarnings("unchecked") final Map<String, Object> idTokenClaims =
        (Map<String, Object>) this.httpSession.getAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS);
    if (idTokenClaims == null) {
      // No authentication result to update
      return new UserInfoCallModel(exchange, null);
    }
    final JWTClaimsSet jwtClaims = (JWTClaimsSet) this.httpSession.getAttribute("jwt_claims");
    try {
      return new UserInfoCallModel(exchange,
          UserInfoEvaluation.evaluate(authRequest, jwtClaims, idTokenClaims, exchange, true));
    }
    catch (final RuntimeException e) {
      log.info("Failed to evaluate UserInfo response: {}", e.getMessage());
      return new UserInfoCallModel(exchange, null);
    }
  }

  @PostMapping(value = "/authn/verify", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public Object verifyOidcResponse(
      @Nonnull @RequestBody final Map<String, Object> response) {
    return response.get("response_data");
  }

  @GetMapping(value = "/rp/metadata")
  public JSONObject getMetadata(@RequestParam("rp") final String entityId) {
    return this.oidcRps.stream().filter(rp -> rp.getEntityId().equals(entityId)).findFirst().orElseThrow(() -> {
      return new RuntimeException("Failed to find metadata for %s".formatted(entityId));
    }).getMetadata().toJSONObject(true);
  }

  @GetMapping(value = "/op/metadata")
  public JSONObject getOpMetadata(@RequestParam("op") final String entityId) {
    return this.fetcher.getOPMetadata(this.opRegistry.get(entityId));
  }

  @GetMapping(value = "/authn/info")
  public OIDCInitAuthnModel initInfo() {
    final List<OpenIdRelyingPartyModel> relyingParties = this.oidcRps.stream()
        .map(rp -> new OpenIdRelyingPartyModel(rp.getEntityId(), rp.getMetadata().getName(), rp.getDescription(),
            this.urlBuilderBean.buildUrl(
                "/oidc/rp/metadata?rp=" + URLEncoder.encode(rp.getEntityId(), Charset.defaultCharset())),
            rp.isUseJwksUrl() ? rp.getJwksUri() : null, entityConfigurationUrl(rp)))
        .toList();

    final List<OpenIdProviderModel> providers = this.opRegistry.getOps().stream()
        .map(op -> new OpenIdProviderModel(
            op.getEntityId(),
            op.getDisplayName(),
            Optional.ofNullable(op.getDescription()).orElse(""),
            op.getMetadataEndpoint()))
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

    final OidcOp selectedOp = this.opRegistry.get(op);

    final JWKSet opJWKS = this.fetcher.getOPJWKS(selectedOp);
    final Optional<JWK> opEncKey = opJWKS.getKeys()
        .stream()
        .filter(jwk -> KeyUse.ENCRYPTION.equals(jwk.getKeyUse()))
        .findFirst()
        .or(() -> opJWKS.getKeys().stream().findFirst());
    final List<KeyModel> encryptionKeys = opJWKS.getKeys()
        .stream()
        .map(jwk -> {
          final KeyModel.KeyModelBuilder builder = KeyModel.builder()
              .alg(Optional.ofNullable(jwk.getKeyType()).map(KeyType::getValue).orElse("?"))
              .kid(jwk.getKeyID())
              .typ("");
          if (opEncKey.map(k -> k.getKeyID().equals(jwk.getKeyID())).orElse(false)) {
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
        .signMessage(createDefaultSignRequest(signKey.getKeyID()))
        .userMessage(createDefaultUserMessage())
        .scope(new ModelParameter("openid", false, true))
        .requestBodyScope("openid")
        .requestMode("request")
        .redirectUri(new ModelParameter(selectedRp.getMetadata().getRedirectionURI().toASCIIString(), false, true))
        .clientId(new ModelParameter(selectedRp.getEntityId(), false, true))
        .acrValues(new ModelParameter("", false, false))
        .claimInRequestBody(false)
        .callUserInfo(true)
        .advanced(createDefaultAdvancedOptions())
        .keys(KeyOptionsParameterModel.builder()
            .signKeys(signKeys)
            .encKeys(encryptionKeys)
            .encKey(opEncKey.map(JWK::getKeyID).orElse(null))
            .signKey(signKey.getKeyID())
            .moduleEnabled(true).build())
        .requestObject(RequestObjectParamterModel.builder()
            .issuer(new ModelParameter(selectedRp.getEntityId(), true, true))
            .audience(new ModelParameter(selectedOp.getTokenEndpoint(), true, true))
            .signRequest(false)
            .encryptRequest(false)
            .moduleEnabled(false).build())
        .build();
  }

  /**
   * Creates the initial sign request of the request builder. The TBS data and messages are Base64-encoded, the
   * message MIME type is {@code text/plain}, and in the request URL the sign request is a signed JWT that is not
   * encrypted.
   *
   * @param signKey the key ID of the RP's registered signing key, which signs the sign request JWT
   * @return the default sign request
   */
  static SignatureParameterModel createDefaultSignRequest(final String signKey) {
    return SignatureParameterModel.builder()
        .b64Encode(true)
        .includeTbsData(true)
        .signMessage(OidcMessageParameterModel.builder().mimeType("text/plain").build())
        .signJwt(true)
        .signKey(signKey)
        .encryptJwt(false)
        .requestBody(false)
        .valuePresent(false)
        .build();
  }

  /**
   * Creates the initial user message of the request builder. The messages are Base64-encoded and the MIME type is
   * {@code text/plain}.
   *
   * @return the default user message
   */
  static OidcMessageParameterModel createDefaultUserMessage() {
    return OidcMessageParameterModel.builder()
        .b64Encode(true)
        .mimeType("text/plain")
        .messageSwedish("msg")
        .valuePresent(false)
        .requestBody(false)
        .build();
  }

  /**
   * Creates the initial advanced options of the request builder. State and nonce are pre-generated, and PKCE (S256) is
   * sent in the request URL.
   *
   * @return the default advanced options
   */
  static AdvancedOptionsParamterModel createDefaultAdvancedOptions() {
    return AdvancedOptionsParamterModel.builder()
        .state(ModelParameter.builder().value(new State().getValue()).valuePresent(true).requestBody(false).build())
        .nonce(ModelParameter.builder().value(new Nonce().getValue()).valuePresent(true).requestBody(false).build())
        .prompt(ModelParameter.builder().value("login").valuePresent(true).requestBody(false).build())
        .loginHint(ModelParameter.builder().value("").valuePresent(false).requestBody(false).build())
        .responseType(ModelParameter.builder().value("code").valuePresent(true).requestBody(false).build())
        .codeChallenge(ModelParameter.builder().valuePresent(true).requestBody(false).build())
        .codeChallengeMethod(ModelParameter.builder().value("S256").valuePresent(true).requestBody(false).build())
        .moduleEnabled(false)
        .build();
  }

  /**
   * Generates an authentication request, and records it in the session as it is sent.
   * <p>
   * The HTTP method is chosen by the send button that is clicked and is not part of the request model. The parameters
   * are the same for both methods (OpenID Connect Core 1.0, section 3.1.2.1): with GET they are in the query string of
   * the returned URL, with POST the URL is the authorization endpoint as configured and they are returned as the form
   * parameters for the browser to post.
   * </p>
   *
   * @param model the request parameter model
   * @param method the HTTP method used to send the request
   * @return the request for the browser to send
   * @throws JOSEException for signing or encryption errors
   * @throws ParseException for invalid parameter values
   */
  @PostMapping(value = "/authn/generate", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public OIDCAuthnRequestModel generateAuthnRequest(
      @Nonnull @RequestBody final OIDCAuthnRequestParameterModel model,
      @Nonnull @RequestParam("method") final SentAuthorizationRequest.Method method
  ) throws JOSEException, ParseException {
    try {
      final OidcRp selectedRp =
          this.oidcRps.stream().filter(rp -> model.getRp().equals(rp.getEntityId())).findFirst()
              .orElseThrow(() -> new RuntimeException("No such relying party found"));

      final OidcOp selectedOp = this.opRegistry.get(model.getOp());

      final JWKSet opJWKS = this.fetcher.getOPJWKS(selectedOp);

      final AuthenticationRequest.Builder builder = new AuthenticationRequest.Builder(
          new ResponseType("code"),
          new Scope("openid"),
          new ClientID(model.getClientId().getValue()),
          URI.create(model.getRedirectUri().getValue()))
          .endpointURI(URI.create(selectedOp.getAuthorizationEndpoint()));

      builder.maxAge(0);

      // A verifier left over from an earlier request must not reach the token request of this one
      httpSession.removeAttribute(AuthorizationParameterResolver.CODE_VERIFIER_ATTRIBUTE);
      final AuthorizationParameterResolver resolver =
          new AuthorizationParameterResolver(model, false, httpSession::setAttribute);
      final AuthenticationRequest authRequest =
          AuthorizationRequestCustomizer.customize(builder, kidtoJwkFunction(opJWKS), resolver).build();
      final SentAuthorizationRequest sentRequest =
          AuthorizationRequestCustomizer.toSentRequest(authRequest, resolver, method);

      httpSession.setAttribute("auth_request", authRequest);
      httpSession.setAttribute(OidcController.SESSION_NAME_SENT_AUTH_REQUEST, sentRequest);
      httpSession.setAttribute("selected_op", selectedOp);
      httpSession.setAttribute("selected_rp", selectedRp);
      // The setting governs the redirection handling of this request only
      httpSession.setAttribute(OidcController.SESSION_NAME_CALL_USERINFO,
          !Boolean.FALSE.equals(model.getCallUserInfo()));
      httpSession.removeAttribute(OidcController.SESSION_NAME_ID_TOKEN_CLAIMS);

      log.info("{} {}", sentRequest.method(), sentRequest.url());
      return OIDCAuthnRequestModel.builder()
          .method(sentRequest.method().name())
          .url(sentRequest.url())
          .parameters(sentRequest.parameters())
          .build();
    }
    catch (final Exception e) {
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

  /**
   * Gets the URL of the entity configuration of the supplied RP.
   *
   * @param rp the Relying Party
   * @return the entity configuration URL, or {@code null} if the RP has no entity configuration
   */
  @Nullable
  private static String entityConfigurationUrl(@Nonnull final OidcRp rp) {
    return rp.hasEntityConfiguration() ? OidfClient.entityConfigurationUrl(rp.getEntityId()) : null;
  }

  @AllArgsConstructor
  @NoArgsConstructor
  @Getter
  @Setter
  @Builder
  public static class OIDCAuthnRequestModel {
    /** The HTTP method, {@code GET} or {@code POST}. */
    private String method;
    /** For GET the full request URL, for POST the authorization endpoint. */
    private String url;
    /** For POST the form parameters, for GET {@code null}. */
    private Map<String, List<String>> parameters;
  }

  /**
   * A UserInfo request to send.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class UserInfoRequestModel {

    /** The access token - if {@code null} or empty, the request is sent without an {@code Authorization} header. */
    @JsonProperty("access_token")
    private String accessToken;

    /** The HTTP method, {@code GET} (default) or {@code POST}. */
    private String method;
  }

  /**
   * The result of a UserInfo request.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class UserInfoCallModel {

    /** The call - the request as sent and what came back. */
    private UserInfoExchange exchange;

    /** The UserInfo parts of the authentication result, or {@code null} if there is no result to update. */
    private UserInfoEvaluation evaluation;
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

    @JsonProperty("jwks_url")
    private String jwksUrl;

    /** The URL of the RP:s entity configuration, or {@code null} if the RP has none. */
    @JsonProperty("entity_configuration_url")
    private String entityConfigurationUrl;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OidcRpInfoModel {
    @JsonProperty("entity-id")
    private String entityId;

    private String description;

    @JsonProperty("metadata_url")
    private String metadataUrl;

    @JsonProperty("jwks_url")
    private String jwksUrl;

    /** The URL of the RP:s entity configuration, or {@code null} if the RP has none. */
    @JsonProperty("entity_configuration_url")
    private String entityConfigurationUrl;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OidcOpInfoModel {
    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("display_name")
    private String displayName;

    private String description;

    @JsonProperty("metadata_url")
    private String metadataUrl;

    /** How the OP was configured - {@code static} or {@code federation}. */
    private String source;

    @JsonProperty("trust_anchor")
    private String trustAnchor;
  }
}
