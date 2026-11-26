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
import jakarta.servlet.http.HttpSession;
import se.swedenconnect.testclient.controllers.TokenExchangeChecks.Check;
import se.swedenconnect.testclient.controllers.TokenExchangeChecks.Outcome;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Checks the client authentication of a request to the token endpoint against section 4.1.1 ("Client Authentication")
 * of the Swedish Digital Gateway (SDG) OAuth 2.0 profile.
 * <p>
 * The checks only report - nothing is rejected. They apply to every request the test client sends to a token endpoint:
 * the token request of an authentication and a token exchange request.
 * </p>
 *
 * @author Simon Tardell
 * @see <a href="https://docs.swedenconnect.se/technical-framework/sdg/sdg-oauth2-profile.html#client-authentication">
 *     SDG OAuth 2.0 profile, section 4.1.1</a>
 */
public final class ClientAuthenticationChecks {

  /** The section of the profile that all the checks are for. */
  public static final String SECTION = "4.1.1";

  /** The client assertion type of a JWT assertion (RFC 7523, section 2.2). */
  public static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  /** The session attribute that holds the jti values of the client assertions sent in this session. */
  public static final String SESSION_JTIS = "client_assertion_jtis";

  /** The entropy that the profile requires of jti. */
  static final int REQUIRED_JTI_BITS = 128;

  private static final Set<String> STANDARD_CLAIMS = Set.of("iss", "sub", "aud", "iat", "exp", "jti");

  private static final Pattern UUID = Pattern.compile(
      "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([0-9a-fA-F])[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

  private ClientAuthenticationChecks() {
  }

  /**
   * Checks the client authentication of a token request.
   *
   * @param request the request as it was sent
   * @param clientId the client ID of the client, used when the request has no {@code client_id} parameter
   * @param earlierJtis the jti values of the client assertions sent earlier in this session
   * @return the checks, in the order of the profile
   */
  @Nonnull
  public static List<Check> evaluate(@Nonnull final SentTokenRequest request, @Nullable final String clientId,
      @Nonnull final Collection<String> earlierJtis) {
    return evaluate(request.url(), request.headers(), request.parameters(), request.clientAssertion(), clientId,
        earlierJtis);
  }

  /**
   * Checks the client authentication of a request to the token endpoint.
   *
   * @param tokenEndpoint the URL the request was sent to
   * @param headers the request headers
   * @param parameters the form parameters (the first value of each)
   * @param assertion the decoded client assertion, or {@code null} if no {@code client_assertion} was sent
   * @param clientId the client ID of the client, used when the request has no {@code client_id} parameter
   * @param earlierJtis the jti values of the client assertions sent earlier in this session
   * @return the checks, in the order of the profile
   */
  @Nonnull
  public static List<Check> evaluate(@Nonnull final String tokenEndpoint, @Nonnull final Map<String, String> headers,
      @Nonnull final Map<String, String> parameters, @Nullable final SentTokenRequest.ClientAssertion assertion,
      @Nullable final String clientId, @Nonnull final Collection<String> earlierJtis) {

    final List<Check> checks = new ArrayList<>();
    final String assertionType = parameters.get("client_assertion_type");
    final boolean hasAssertion = parameters.get("client_assertion") != null;
    final boolean basic = headers.entrySet().stream()
        .anyMatch(h -> "Authorization".equalsIgnoreCase(h.getKey()) && h.getValue() != null
            && h.getValue().regionMatches(true, 0, "Basic ", 0, 6));
    final boolean secret = parameters.get("client_secret") != null;
    final String alg = assertion != null && assertion.header() != null
        ? Optional.ofNullable(assertion.header().get("alg")).map(String::valueOf).orElse(null)
        : null;
    final boolean symmetric = alg != null && alg.toUpperCase().startsWith("HS");

    // The method
    final List<String> other = new ArrayList<>();
    if (basic) {
      other.add("an Authorization: Basic header (client_secret_basic)");
    }
    if (secret) {
      other.add("a client_secret parameter (client_secret_post)");
    }
    if (symmetric) {
      other.add("an assertion signed with " + alg + " (client_secret_jwt)");
    }
    if (!hasAssertion && other.isEmpty()) {
      other.add("no client authentication");
    }
    check(checks, "MUST", "The client authenticates with private_key_jwt only", hasAssertion && other.isEmpty(),
        other.isEmpty() ? "private_key_jwt" : "The request has " + String.join(" and ", other));

    // The parameters
    check(checks, "MUST", "client_assertion_type is " + JWT_BEARER, JWT_BEARER.equals(assertionType),
        "client_assertion_type=" + assertionType);
    check(checks, "MUST", "client_assertion is included", hasAssertion, null);
    if (!hasAssertion) {
      return checks;
    }
    if (assertion == null || assertion.claims() == null || assertion.header() == null) {
      checks.add(new Check(SECTION, "MUST", "The client assertion is a signed JWT", Outcome.FAIL,
          Optional.ofNullable(assertion).map(SentTokenRequest.ClientAssertion::error)
              .orElse("The client assertion could not be decoded")));
      return checks;
    }
    final Map<String, Object> claims = assertion.claims();

    // The signature
    final boolean asymmetric = alg != null && (alg.startsWith("RS") || alg.startsWith("PS") || alg.startsWith("ES")
        || "EdDSA".equals(alg));
    check(checks, "MUST", "The assertion is signed with the client's private key", asymmetric,
        "alg=" + alg + (asymmetric ? "" : " - not an asymmetric algorithm")
            + " (the allowed algorithms are in section 7.1 of the Swedish OpenID Connect profile)");

    // The claims
    final String client = Optional.ofNullable(parameters.get("client_id")).orElse(clientId);
    final Object iss = claims.get("iss");
    final Object sub = claims.get("sub");
    if (client != null) {
      check(checks, "MUST", "iss is the client ID", Objects.equals(client, iss),
          "iss=%s, client ID=%s".formatted(iss, client));
      check(checks, "MUST", "sub is the client ID", Objects.equals(client, sub),
          "sub=%s, client ID=%s".formatted(sub, client));
    }
    else {
      check(checks, "MUST", "iss and sub are the client ID", iss != null && Objects.equals(iss, sub),
          "iss=%s, sub=%s".formatted(iss, sub));
    }

    final Object aud = claims.get("aud");
    final boolean audIsEndpoint = tokenEndpoint.equals(aud)
        || aud instanceof final Collection<?> c && c.size() == 1 && tokenEndpoint.equals(String.valueOf(
            c.iterator().next()));
    check(checks, "MUST", "aud is the URL of the token endpoint", audIsEndpoint,
        "aud=%s, token endpoint=%s".formatted(aud, tokenEndpoint));

    final Long iat = number(claims.get("iat"));
    final Long exp = number(claims.get("exp"));
    check(checks, "MUST", "iat (the time the assertion was created) is included", iat != null, "iat=" + claims.get(
        "iat"));
    if (exp == null) {
      checks.add(new Check(SECTION, "MUST", "exp (the expiration time) is included", Outcome.FAIL,
          "exp=" + claims.get("exp")));
    }
    else {
      final boolean afterIat = iat == null || exp > iat;
      check(checks, "MUST", "exp (the expiration time) is included", afterIat,
          "exp=" + exp + (iat != null ? " (%d s after iat%s)".formatted(exp - iat, afterIat ? "" : " - not after iat")
              : ""));
    }

    final String jti = Optional.ofNullable(claims.get("jti")).map(String::valueOf).orElse(null);
    if (jti == null || jti.isEmpty()) {
      checks.add(new Check(SECTION, "MUST", "jti is included and has at least 128 bits of entropy", Outcome.FAIL,
          "No jti"));
    }
    else {
      final Entropy entropy = estimateEntropy(jti);
      check(checks, "MUST", "jti is included and has at least 128 bits of entropy",
          entropy.bits() >= REQUIRED_JTI_BITS, "jti=%s - %s".formatted(jti, entropy.explanation()));
      final boolean reused = earlierJtis.contains(jti);
      check(checks, "MUST", "A new assertion is used for each request (jti not used before)", !reused,
          reused ? "This jti was sent in an earlier token request in this session"
              : "jti not used in an earlier token request in this session");
    }

    final List<String> additional = claims.keySet().stream().filter(k -> !STANDARD_CLAIMS.contains(k)).toList();
    checks.add(new Check(SECTION, "MAY", "Additional claims", Outcome.INFO,
        additional.isEmpty() ? "None" : String.join(", ", additional)));
    return checks;
  }

  /**
   * Gets the jti values of the client assertions sent in this session.
   *
   * @param session the HTTP session
   * @return the jti values (a copy)
   */
  @Nonnull
  public static Set<String> earlierJtis(@Nonnull final HttpSession session) {
    return session.getAttribute(SESSION_JTIS) instanceof final Set<?> s
        ? new LinkedHashSet<>(s.stream().map(String::valueOf).toList())
        : new LinkedHashSet<>();
  }

  /**
   * Remembers the jti of a client assertion that was sent, so that a later request that uses it again is reported.
   *
   * @param session the HTTP session
   * @param assertion the decoded client assertion, or {@code null}
   */
  public static void rememberJti(@Nonnull final HttpSession session,
      @Nullable final SentTokenRequest.ClientAssertion assertion) {
    if (assertion == null || assertion.claims() == null || assertion.claims().get("jti") == null) {
      return;
    }
    final Set<String> jtis = earlierJtis(session);
    jtis.add(String.valueOf(assertion.claims().get("jti")));
    session.setAttribute(SESSION_JTIS, jtis);
  }

  /**
   * An estimate of the entropy of a jti value.
   *
   * @param bits the estimated number of bits
   * @param explanation how the estimate was made
   */
  record Entropy(double bits, @Nonnull String explanation) {
  }

  /**
   * Estimates the entropy of a jti value. Only its form can be seen, not how it was generated, so the estimate is an
   * upper bound: a random UUID (version 4) has 122 random bits, and other values at most their length times the bits of
   * the smallest alphabet that holds all their characters.
   *
   * @param jti the jti value
   * @return the estimate
   */
  @Nonnull
  static Entropy estimateEntropy(@Nonnull final String jti) {
    final var uuid = UUID.matcher(jti);
    if (uuid.matches()) {
      return "4".equals(uuid.group(1))
          ? new Entropy(122, "a random UUID (version 4), which has 122 random bits")
          : new Entropy(0, "a UUID of version %s, which is not random".formatted(uuid.group(1)));
    }
    final String alphabet;
    final int size;
    if (jti.matches("[0-9]+")) {
      alphabet = "digits";
      size = 10;
    }
    else if (jti.matches("[0-9a-f]+") || jti.matches("[0-9A-F]+")) {
      alphabet = "hexadecimal";
      size = 16;
    }
    else if (jti.matches("[0-9A-Za-z]+")) {
      alphabet = "alphanumeric";
      size = 62;
    }
    else if (jti.matches("[0-9A-Za-z_-]+") || jti.matches("[0-9A-Za-z+/]+=*")) {
      alphabet = "Base64";
      size = 64;
    }
    else {
      alphabet = "printable ASCII";
      size = 95;
    }
    final int length = alphabet.equals("Base64") ? jti.replace("=", "").length() : jti.length();
    final double bits = length * (Math.log(size) / Math.log(2));
    return new Entropy(bits, "at most %d bits (%d %s characters); the actual entropy depends on how it was generated"
        .formatted((int) Math.floor(bits), length, alphabet));
  }

  @Nullable
  private static Long number(@Nullable final Object value) {
    if (value instanceof final Number n) {
      return n.longValue();
    }
    if (value instanceof final java.util.Date d) {
      return d.getTime() / 1000;
    }
    try {
      return value == null ? null : Long.parseLong(String.valueOf(value));
    }
    catch (final NumberFormatException e) {
      return null;
    }
  }

  private static void check(@Nonnull final List<Check> checks, @Nonnull final String level,
      @Nonnull final String requirement, final boolean met, @Nullable final String detail) {
    checks.add(new Check(SECTION, level, requirement, met ? Outcome.PASS : Outcome.FAIL, detail));
  }
}
