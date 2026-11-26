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
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Checks a token exchange request and its response against the Ena OAuth 2.0 Token Exchange Profile for Chaining
 * Identity and Authorization, section 2 ("Protected Resource Acting as a Client").
 * <p>
 * The checks only report - nothing is rejected. A check that cannot be made (for example because a token is not a JWT)
 * is left out.
 * </p>
 *
 * @author Simon Tardell
 * @see <a href="https://ena-infrastructure.github.io/specifications/ena-oauth2-chaining.html">Ena chaining
 *     profile</a>
 */
public final class TokenExchangeChecks {

  /** The token exchange grant type (RFC 8693, section 2.1). */
  public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

  /** The token type URI of an access token (RFC 8693, section 3). */
  public static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

  /** The outcome of a check. */
  public enum Outcome {
    /** The requirement is met. */
    PASS,
    /** The requirement is not met. */
    FAIL,
    /** Information - nothing is required, or the requirement depends on the deployment. */
    INFO
  }

  /**
   * The result of a check.
   *
   * @param section the section of the profile
   * @param level the requirement level, e.g. MUST or SHOULD
   * @param requirement what is required
   * @param outcome the outcome
   * @param detail what was found
   */
  public record Check(@Nonnull String section, @Nonnull String level, @Nonnull String requirement,
      @Nonnull Outcome outcome, @Nullable String detail) {
  }

  private TokenExchangeChecks() {
  }

  /**
   * Checks a token exchange request and, if one was received, the token response and the issued token.
   *
   * @param request the form parameters that were sent
   * @param subjectTokenClaims the claims of the subject token, or {@code null} if it is not a JWT
   * @param response the token response, or {@code null} if no token response was received
   * @param issuedTokenClaims the claims of the issued access token, or {@code null} if it is not a JWT
   * @return the checks, in the order of the profile
   */
  @Nonnull
  public static List<Check> evaluate(@Nonnull final MultiValueMap<String, String> request,
      @Nullable final Map<String, Object> subjectTokenClaims, @Nullable final Map<String, Object> response,
      @Nullable final Map<String, Object> issuedTokenClaims) {

    final List<Check> checks = new ArrayList<>();
    final List<String> targets = new ArrayList<>();
    Optional.ofNullable(request.get("resource")).ifPresent(targets::addAll);
    Optional.ofNullable(request.get("audience")).ifPresent(targets::addAll);
    final String requestedScope = request.getFirst("scope");

    // 2.3 - the request
    check(checks, "2.3", "MUST", "grant_type is " + GRANT_TYPE, GRANT_TYPE.equals(request.getFirst("grant_type")),
        "grant_type=" + request.getFirst("grant_type"));
    check(checks, "2.3", "MUST", "subject_token_type is " + ACCESS_TOKEN_TYPE,
        ACCESS_TOKEN_TYPE.equals(request.getFirst("subject_token_type")),
        "subject_token_type=" + request.getFirst("subject_token_type"));
    if (!targets.isEmpty()) {
      checks.add(new Check("2.3", "MUST", "A target indicator (resource or audience) is included", Outcome.PASS,
          String.join(" ", targets)));
    }
    else if (requestedScope != null) {
      checks.add(new Check("2.3", "MUST", "A target indicator (resource or audience) is included", Outcome.INFO,
          "No resource or audience - allowed if the AS can deduce the target from scope=" + requestedScope));
    }
    else {
      checks.add(new Check("2.3", "MUST", "A target indicator (resource or audience) is included", Outcome.FAIL,
          "Neither resource, audience nor scope was sent"));
    }
    check(checks, "2.3", "SHOULD", "requested_token_type is " + ACCESS_TOKEN_TYPE,
        ACCESS_TOKEN_TYPE.equals(request.getFirst("requested_token_type")),
        "requested_token_type=" + request.getFirst("requested_token_type"));

    if (response == null) {
      return checks;
    }

    // 2.4 - the token response
    check(checks, "2.4", "MUST", "The response includes access_token", response.get("access_token") != null, null);
    check(checks, "2.4", "MUST", "issued_token_type is " + ACCESS_TOKEN_TYPE,
        ACCESS_TOKEN_TYPE.equals(response.get("issued_token_type")),
        "issued_token_type=" + response.get("issued_token_type"));
    check(checks, "2.4", "MUST", "token_type is Bearer (or DPoP for a DPoP-bound token)",
        response.get("token_type") instanceof final String t
            && ("Bearer".equalsIgnoreCase(t) || "DPoP".equalsIgnoreCase(t)),
        "token_type=" + response.get("token_type"));
    check(checks, "2.4", "MUST NOT", "No refresh token is issued (unless local policy says otherwise)",
        response.get("refresh_token") == null,
        response.get("refresh_token") == null ? null : "A refresh_token was issued");
    check(checks, "2.4", "RECOMMENDED", "The response includes scope", response.get("scope") != null,
        "scope=" + response.get("scope"));

    if (issuedTokenClaims == null) {
      checks.add(new Check("2.4", "-", "Claims of the issued access token", Outcome.INFO,
          "The issued access token is not a JWT - its claims cannot be checked"));
      return checks;
    }

    // 2.4 - the issued access token
    final List<String> aud = stringList(issuedTokenClaims.get("aud"));
    if (!targets.isEmpty()) {
      final List<String> missing = targets.stream().filter(t -> !aud.contains(t)).toList();
      check(checks, "2.4", "MUST", "aud corresponds to the requested resource/audience", missing.isEmpty(),
          "aud=" + aud + (missing.isEmpty() ? "" : ", missing " + missing));
    }
    else {
      checks.add(new Check("2.4", "MUST", "aud corresponds to the requested resource/audience", Outcome.INFO,
          "aud=" + aud + " (no resource or audience was requested)"));
    }

    if (subjectTokenClaims != null) {
      check(checks, "2.4", "MUST", "sub is the sub of the subject token",
          Objects.equals(subjectTokenClaims.get("sub"), issuedTokenClaims.get("sub")),
          "subject token sub=%s, issued token sub=%s".formatted(subjectTokenClaims.get("sub"),
              issuedTokenClaims.get("sub")));
      for (final String claim : List.of("acr", "amr", "auth_time")) {
        if (subjectTokenClaims.containsKey(claim)) {
          check(checks, "2.4", "MUST", claim + " of the subject token is preserved",
              Objects.equals(String.valueOf(subjectTokenClaims.get(claim)),
                  String.valueOf(issuedTokenClaims.get(claim))),
              "subject token %s=%s, issued token %s=%s".formatted(claim, subjectTokenClaims.get(claim), claim,
                  issuedTokenClaims.get(claim)));
        }
      }
    }

    final String clientId = Optional.ofNullable(issuedTokenClaims.get("client_id")).map(String::valueOf).orElse(null);
    checks.add(new Check("2.4.1", "-", "client_id is the client that requested the exchange", Outcome.INFO,
        clientId != null
            ? "client_id=" + clientId
            : "No client_id claim" + Optional.ofNullable(issuedTokenClaims.get("azp")).map(a -> " (azp=" + a + ")")
                .orElse("")));

    final Object act = issuedTokenClaims.get("act");
    if (act instanceof final Map<?, ?> actMap) {
      checks.add(new Check("2.4", "SHOULD", "act identifies the current and originating actors", Outcome.PASS,
          "act=" + act));
      final Object actSub = actMap.get("sub");
      final String requester = Optional.ofNullable(clientId).orElseGet(() -> request.getFirst("client_id"));
      if (requester != null) {
        check(checks, "2.4.1", "MUST", "act.sub is the client that requested the exchange",
            Objects.equals(requester, actSub), "act.sub=%s, client=%s".formatted(actSub, requester));
      }
    }
    else {
      checks.add(new Check("2.4", "SHOULD", "act identifies the current and originating actors", Outcome.FAIL,
          act == null ? "No act claim" : "act is not a JSON object"));
    }

    if (subjectTokenClaims != null && issuedTokenClaims.get("scope") instanceof final String issuedScope) {
      final Set<String> subjectScopes = scopes(subjectTokenClaims.get("scope"));
      final List<String> added = scopes(issuedScope).stream().filter(s -> !subjectScopes.contains(s)).toList();
      checks.add(new Check("2.3.1", "-", "Scopes of the issued token that the subject token does not have",
          Outcome.INFO, added.isEmpty()
              ? "None"
              : String.join(" ", added) + " - where the user is the resource owner, the AS may only grant scopes"
                  + " the user originally authorized"));
    }
    return checks;
  }

  private static void check(@Nonnull final List<Check> checks, @Nonnull final String section,
      @Nonnull final String level, @Nonnull final String requirement, final boolean met,
      @Nullable final String detail) {
    checks.add(new Check(section, level, requirement, met ? Outcome.PASS : Outcome.FAIL, detail));
  }

  @Nonnull
  private static List<String> stringList(@Nullable final Object value) {
    if (value instanceof final Collection<?> c) {
      return c.stream().map(String::valueOf).toList();
    }
    return value == null ? List.of() : List.of(String.valueOf(value));
  }

  @Nonnull
  private static Set<String> scopes(@Nullable final Object scope) {
    if (scope == null) {
      return Set.of();
    }
    return new LinkedHashSet<>(Arrays.stream(String.valueOf(scope).trim().split("\\s+"))
        .filter(s -> !s.isEmpty()).toList());
  }
}
