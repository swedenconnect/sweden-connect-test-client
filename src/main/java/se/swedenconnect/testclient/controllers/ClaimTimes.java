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

import java.math.BigInteger;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Gets the times, in UTC, of the time claims of a received claim set - so that the authentication result can show
 * {@code 1789650256 (2026-09-17 13:04:16 UTC)} instead of only the seconds since epoch. The claims themselves are not
 * changed.
 * <p>
 * Only the top-level claims {@code exp}, {@code iat}, {@code nbf}, {@code auth_time} and {@code updated_at} are
 * treated as times, and only if their value is a whole number, zero or greater, that a time can be computed for. Any
 * other value - a string (also one holding digits), a decimal, a negative number, a number out of range, a boolean,
 * an object or a list - is given no time.
 * </p>
 *
 * @author Martin Lindström
 */
public final class ClaimTimes {

  /** The names of the claims that are treated as times. */
  public static final List<String> TIME_CLAIMS = List.of("exp", "iat", "nbf", "auth_time", "updated_at");

  private static final DateTimeFormatter FORMATTER =
      DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC);

  private ClaimTimes() {
  }

  /**
   * Gets the times of the time claims of a claim set.
   *
   * @param claims the received claims (may be {@code null})
   * @return a map of each time claim that a time could be computed for, to that time in UTC - e.g.,
   *     {@code 2026-09-17 13:04:16 UTC}
   */
  @Nonnull
  public static Map<String, String> of(@Nullable final Map<String, Object> claims) {
    final Map<String, String> times = new LinkedHashMap<>();
    if (claims == null) {
      return times;
    }
    for (final String claim : TIME_CLAIMS) {
      if (claims.containsKey(claim)) {
        format(claims.get(claim)).ifPresent(time -> times.put(claim, time));
      }
    }
    return times;
  }

  /**
   * Formats a claim value, holding seconds since epoch, as a time in UTC.
   *
   * @param value the claim value (may be {@code null})
   * @return the time in UTC, or an empty {@link Optional} if the value is not a whole number, zero or greater, that a
   *     time can be computed for
   */
  @Nonnull
  static Optional<String> format(@Nullable final Object value) {
    final long seconds;
    if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
      seconds = ((Number) value).longValue();
    }
    else if (value instanceof final BigInteger bigInteger) {
      if (bigInteger.bitLength() >= Long.SIZE) {
        return Optional.empty();
      }
      seconds = bigInteger.longValue();
    }
    else {
      // Decimals (Double, Float, BigDecimal), strings, booleans, objects and lists are not times
      return Optional.empty();
    }
    if (seconds < 0) {
      return Optional.empty();
    }
    try {
      return Optional.of(FORMATTER.format(Instant.ofEpochSecond(seconds)));
    }
    catch (final DateTimeException e) {
      return Optional.empty();
    }
  }
}
