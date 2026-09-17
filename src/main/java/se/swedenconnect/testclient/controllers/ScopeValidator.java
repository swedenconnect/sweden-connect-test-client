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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.testclient.oidc.ScopeClaimRegistry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Checks, for each requested scope, whether the claims that the scope is defined to deliver were received.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
public final class ScopeValidator {

  /**
   * Gets the scopes that were requested, either as a request parameter or in the request object.
   *
   * @param authRequest the authentication request
   * @param jwtClaims the claims of the request object (may be {@code null})
   * @return the requested scopes
   */
  @Nonnull
  public static List<String> requestedScopes(@Nonnull final AuthenticationRequest authRequest,
      @Nullable final JWTClaimsSet jwtClaims) {
    final List<String> scopes = new ArrayList<>(
        Optional.ofNullable(authRequest.getScope()).map(Scope::toStringList).orElseGet(List::of));

    Optional.ofNullable(jwtClaims)
        .map(claims -> claims.getClaim("scope"))
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .ifPresent(scope -> Arrays.stream(scope.split("\\s+"))
            .filter(s -> !s.isBlank())
            .filter(s -> !scopes.contains(s))
            .forEach(scopes::add));

    return scopes;
  }

  /**
   * Checks, for each requested scope, whether the claims that the scope is defined to deliver were received.
   * <p>
   * If the UserInfo claims could not be checked - UserInfo was not called, or the call failed - a claim that is
   * expected from UserInfo and was not received in the ID token is reported as not checked rather than as missing,
   * and a scope is not reported as missing only because of such claims.
   * </p>
   *
   * @param scopes the requested scopes
   * @param idTokenClaims the claims of the ID Token
   * @param userInfoClaims the claims received from the UserInfo endpoint
   * @param userInfoNotCheckedReason why the UserInfo claims could not be checked, or {@code null} if they were
   * @return one result per requested scope
   */
  @Nonnull
  public static List<ScopeValidationResult> validate(@Nonnull final List<String> scopes,
      @Nullable final Map<String, Object> idTokenClaims, @Nullable final Map<String, Object> userInfoClaims,
      @Nullable final String userInfoNotCheckedReason) {

    return scopes.stream()
        .map(scope -> {
          final Optional<List<ScopeClaimRegistry.ScopeClaim>> registered = ScopeClaimRegistry.getClaims(scope);
          if (registered.isEmpty()) {
            return ScopeValidationResult.builder()
                .scope(scope)
                .status(ScopeValidationResult.Status.UNKNOWN)
                .message("The scope is not defined by the Swedish OpenID Connect or Sweden Connect specifications")
                .build();
          }
          final List<ScopeClaimRegistry.ScopeClaim> scopeClaims = registered.get();
          if (scopeClaims.isEmpty()) {
            return ScopeValidationResult.builder()
                .scope(scope)
                .status(ScopeValidationResult.Status.NO_CLAIMS)
                .message("The scope does not by itself deliver any claims")
                .build();
          }

          final List<ScopeValidationResult.ClaimValidationResult> results = scopeClaims.stream()
              .map(claim -> {
                final List<String> receivedIn = new ArrayList<>();
                if (Objects.nonNull(idTokenClaims) && idTokenClaims.containsKey(claim.name())) {
                  receivedIn.add(ScopeClaimRegistry.Location.ID_TOKEN.getDisplayName());
                }
                if (Objects.nonNull(userInfoClaims) && userInfoClaims.containsKey(claim.name())) {
                  receivedIn.add(ScopeClaimRegistry.Location.USER_INFO.getDisplayName());
                }
                final boolean notChecked = receivedIn.isEmpty()
                    && Objects.nonNull(userInfoNotCheckedReason)
                    && claim.location() == ScopeClaimRegistry.Location.USER_INFO;
                return ScopeValidationResult.ClaimValidationResult.builder()
                    .claim(claim.name())
                    .expectedLocation(claim.location().getDisplayName())
                    .requirement(claim.requirement().name())
                    .received(!receivedIn.isEmpty())
                    .receivedIn(receivedIn.isEmpty() ? null : String.join(", ", receivedIn))
                    .notCheckedReason(notChecked ? userInfoNotCheckedReason : null)
                    .build();
              })
              .toList();

          final List<String> missingMandatory = results.stream()
              .filter(r -> ScopeClaimRegistry.Requirement.MANDATORY.name().equals(r.getRequirement()))
              .filter(r -> !r.isReceived() && !r.isNotChecked())
              .map(ScopeValidationResult.ClaimValidationResult::getClaim)
              .toList();

          final List<ScopeValidationResult.ClaimValidationResult> oneOf = results.stream()
              .filter(r -> ScopeClaimRegistry.Requirement.ONE_OF.name().equals(r.getRequirement()))
              .toList();
          final long oneOfReceived = oneOf.stream()
              .filter(ScopeValidationResult.ClaimValidationResult::isReceived)
              .count();
          final boolean oneOfNotChecked = oneOf.stream()
              .anyMatch(ScopeValidationResult.ClaimValidationResult::isNotChecked);
          final boolean anyNotChecked = results.stream()
              .anyMatch(ScopeValidationResult.ClaimValidationResult::isNotChecked);

          final ScopeValidationResult.ScopeValidationResultBuilder builder = ScopeValidationResult.builder()
              .scope(scope)
              .claims(results);

          if (!missingMandatory.isEmpty()) {
            return builder
                .status(ScopeValidationResult.Status.MISSING)
                .message("Missing claim(s): %s".formatted(String.join(", ", missingMandatory)))
                .build();
          }
          if (!oneOf.isEmpty() && oneOfReceived == 0 && !oneOfNotChecked) {
            return builder
                .status(ScopeValidationResult.Status.MISSING)
                .message("None of the mutually exclusive claims of the scope was received")
                .build();
          }
          if (oneOfReceived > 1) {
            return builder
                .status(ScopeValidationResult.Status.WARNING)
                .message("The claims of the scope are mutually exclusive, but more than one was received")
                .build();
          }
          if (anyNotChecked) {
            return builder
                .status(ScopeValidationResult.Status.NOT_CHECKED)
                .message("The claims expected from UserInfo were not checked, %s".formatted(userInfoNotCheckedReason))
                .build();
          }
          return builder.status(ScopeValidationResult.Status.OK).build();
        })
        .toList();
  }

  private ScopeValidator() {
  }
}
