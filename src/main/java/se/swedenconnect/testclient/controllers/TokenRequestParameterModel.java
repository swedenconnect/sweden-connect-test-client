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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Optional;
import java.util.function.Function;

/**
 * The editable settings of the token request that is sent when the OP redirects back with an authorization code - the
 * client authentication method, the form parameters and the claims of the client assertion.
 * <p>
 * Each parameter and claim is a {@link ModelParameter} where {@code valuePresent} tells whether it is included, and
 * {@code value} is its value. For the parameters and claims that are filled in at time of sending ({@code code},
 * {@code code_verifier}, {@code client_assertion}, {@code iat}, {@code jti} and {@code exp}) an empty value means that
 * the test client fills in the value when the request is sent. A {@code null} parameter or claim - as in requests
 * exported before the settings existed - gets its default.
 * </p>
 *
 * @author Martin Lindström
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class TokenRequestParameterModel {

  /** The client authentication method {@code private_key_jwt}. */
  public static final String PRIVATE_KEY_JWT = "private_key_jwt";

  /** The client authentication method {@code client_secret_jwt}. */
  public static final String CLIENT_SECRET_JWT = "client_secret_jwt";

  /** The client authentication method {@code client_secret_post}. */
  public static final String CLIENT_SECRET_POST = "client_secret_post";

  /** The client authentication method {@code client_secret_basic}. */
  public static final String CLIENT_SECRET_BASIC = "client_secret_basic";

  /** The client authentication method {@code none}. */
  public static final String NONE = "none";

  /** The {@code client_assertion_type} for JWT client assertions (RFC 7523, section 2.2). */
  public static final String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  /** The client authentication method. {@code null} means {@code private_key_jwt}. */
  private String authMethod;

  /** Whether the "Token request options" section is open. Only used by the UI. */
  private Boolean moduleEnabled;

  private ModelParameter grantType;
  private ModelParameter code;
  private ModelParameter redirectUri;
  private ModelParameter codeVerifier;
  private ModelParameter clientId;
  private ModelParameter clientSecret;
  private ModelParameter clientAssertionType;
  private ModelParameter clientAssertion;

  private ModelParameter assertionIss;
  private ModelParameter assertionSub;
  private ModelParameter assertionAud;
  private ModelParameter assertionIat;
  private ModelParameter assertionJti;
  private ModelParameter assertionExp;

  /**
   * Creates the default settings - with them the token request is sent with {@code private_key_jwt} and the contents
   * that the test client has always sent.
   *
   * @param entityId the entity ID of the RP
   * @param redirectUri the redirect URI of the RP
   * @param opIssuer the issuer identifier of the OP - the default audience of the client assertion
   * @return the default settings
   */
  @Nonnull
  public static TokenRequestParameterModel defaults(@Nullable final String entityId,
      @Nullable final String redirectUri, @Nullable final String opIssuer) {
    return TokenRequestParameterModel.builder()
        .authMethod(PRIVATE_KEY_JWT)
        .moduleEnabled(false)
        .grantType(row("authorization_code", true))
        .code(row("", true))
        .redirectUri(row(redirectUri, true))
        .codeVerifier(row("", true))
        .clientId(row(entityId, false))
        .clientSecret(row("", false))
        .clientAssertionType(row(JWT_BEARER_ASSERTION_TYPE, true))
        .clientAssertion(row("", true))
        .assertionIss(row(entityId, true))
        .assertionSub(row(entityId, true))
        .assertionAud(row(opIssuer, true))
        .assertionIat(row("", true))
        .assertionJti(row("", true))
        .assertionExp(row("", true))
        .build();
  }

  /**
   * Gets these settings with each missing parameter or claim, and a missing authentication method, taken from the
   * supplied defaults.
   *
   * @param settings the settings (may be {@code null})
   * @param defaults the default settings
   * @return the complete settings
   */
  @Nonnull
  public static TokenRequestParameterModel withDefaults(@Nullable final TokenRequestParameterModel settings,
      @Nonnull final TokenRequestParameterModel defaults) {
    if (settings == null) {
      return defaults;
    }
    final Function<Function<TokenRequestParameterModel, ModelParameter>, ModelParameter> pick =
        getter -> Optional.ofNullable(getter.apply(settings)).orElseGet(() -> getter.apply(defaults));
    return TokenRequestParameterModel.builder()
        .authMethod(Optional.ofNullable(settings.getAuthMethod()).orElse(defaults.getAuthMethod()))
        .moduleEnabled(settings.getModuleEnabled())
        .grantType(pick.apply(TokenRequestParameterModel::getGrantType))
        .code(pick.apply(TokenRequestParameterModel::getCode))
        .redirectUri(pick.apply(TokenRequestParameterModel::getRedirectUri))
        .codeVerifier(pick.apply(TokenRequestParameterModel::getCodeVerifier))
        .clientId(pick.apply(TokenRequestParameterModel::getClientId))
        .clientSecret(pick.apply(TokenRequestParameterModel::getClientSecret))
        .clientAssertionType(pick.apply(TokenRequestParameterModel::getClientAssertionType))
        .clientAssertion(pick.apply(TokenRequestParameterModel::getClientAssertion))
        .assertionIss(pick.apply(TokenRequestParameterModel::getAssertionIss))
        .assertionSub(pick.apply(TokenRequestParameterModel::getAssertionSub))
        .assertionAud(pick.apply(TokenRequestParameterModel::getAssertionAud))
        .assertionIat(pick.apply(TokenRequestParameterModel::getAssertionIat))
        .assertionJti(pick.apply(TokenRequestParameterModel::getAssertionJti))
        .assertionExp(pick.apply(TokenRequestParameterModel::getAssertionExp))
        .build();
  }

  private static ModelParameter row(@Nullable final String value, final boolean included) {
    return ModelParameter.builder().value(value).valuePresent(included).requestBody(false).build();
  }
}
