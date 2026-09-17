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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.minidev.json.JSONObject;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The parts of an OIDC authentication result that depend on the UserInfo call - the UserInfo claims and how they were
 * protected, the requested UserInfo claims that were missing, and the scope validation.
 *
 * @author Martin Lindström
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoEvaluation {

  /** The outcome of the UserInfo call. */
  private UserInfoResult userInfoResult;

  /** The UserInfo claims ({@code null} unless they were received). */
  private Map<String, Object> userInfoClaims;

  /** How the UserInfo response was protected ({@code null} unless the claims were received). */
  private ProtectionInfo userInfoProtection;

  /** The requested UserInfo claims that were not received ({@code null} unless the claims were received). */
  private Map<String, Object> missingUserInfoClaims;

  /** The scope validation. */
  private List<ScopeValidationResult> scopeValidation;

  /**
   * Evaluates a UserInfo call.
   *
   * @param authRequest the authentication request
   * @param jwtClaims the claims of the request object (may be {@code null})
   * @param idTokenClaims the claims of the ID token
   * @param exchange the UserInfo call, or {@code null} if no call was made
   * @param manual whether the call was made manually
   * @return the evaluation
   */
  @Nonnull
  public static UserInfoEvaluation evaluate(@Nonnull final AuthenticationRequest authRequest,
      @Nullable final JWTClaimsSet jwtClaims, @Nullable final Map<String, Object> idTokenClaims,
      @Nullable final UserInfoExchange exchange, final boolean manual) {

    final List<String> scopes = ScopeValidator.requestedScopes(authRequest, jwtClaims);
    if (exchange == null || !exchange.isSuccessful()) {
      final UserInfoResult result = exchange == null
          ? UserInfoResult.notCalled()
          : UserInfoResult.failed(exchange, manual);
      return UserInfoEvaluation.builder()
          .userInfoResult(result)
          .scopeValidation(ScopeValidator.validate(scopes, idTokenClaims, null, result.notCheckedReason()))
          .build();
    }

    final Map<String, Object> userInfo = exchange.getClaims();
    final UserInfoEvaluation.UserInfoEvaluationBuilder builder = UserInfoEvaluation.builder()
        .userInfoResult(UserInfoResult.received(manual))
        .userInfoClaims(userInfo)
        .userInfoProtection(exchange.getProtection())
        .scopeValidation(ScopeValidator.validate(scopes, idTokenClaims, userInfo, null));

    requestedClaims(authRequest, jwtClaims)
        .map(OIDCClaimsRequest::getUserInfoClaimsRequest)
        .map(ClaimsSetRequest::toJSONObject)
        .ifPresent(missing -> {
          userInfo.forEach((key, value) -> missing.remove(key));
          builder.missingUserInfoClaims(missing);
        });
    return builder.build();
  }

  /**
   * Gets the claims that were requested - from the {@code claims} parameter of the authentication request, or else
   * from the request object claims.
   *
   * @param authRequest the authentication request
   * @param jwtClaims the claims of the request object (may be {@code null})
   * @return the requested claims, or an empty {@link Optional} if none were requested
   */
  @Nonnull
  public static Optional<OIDCClaimsRequest> requestedClaims(@Nonnull final AuthenticationRequest authRequest,
      @Nullable final JWTClaimsSet jwtClaims) {
    return Optional.ofNullable(authRequest.getOIDCClaims())
        .or(() -> {
          if (Objects.isNull(jwtClaims)) {
            return Optional.empty();
          }
          try {
            final Map<String, Object> claims = jwtClaims.toJSONObject();
            if (Objects.isNull(claims)) {
              return Optional.empty();
            }
            return Optional.of(OIDCClaimsRequest.parse(new JSONObject(claims)));
          }
          catch (final com.nimbusds.oauth2.sdk.ParseException e) {
            throw new RuntimeException(e);
          }
        });
  }
}
