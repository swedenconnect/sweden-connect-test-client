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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ClaimTimes}.
 *
 * @author Martin Lindström
 */
class ClaimTimesTest {

  private static final long SECONDS = 1789650256L;
  private static final String TIME = "2026-09-17 13:04:16 UTC";
  private static final long LATEST = LocalDateTime.MAX.toEpochSecond(ZoneOffset.UTC);

  @ParameterizedTest
  @ValueSource(strings = { "exp", "iat", "nbf", "auth_time", "updated_at" })
  void eachTimeClaimIsGivenATime(final String claim) {
    assertEquals(Map.of(claim, TIME), ClaimTimes.of(Map.of(claim, SECONDS)));
  }

  @ParameterizedTest
  @ValueSource(strings = { "expires_in", "EXP", "Iat", "exp ", "iat_x", "sub", "birthdate" })
  void otherClaimsAreNotGivenATime(final String claim) {
    assertEquals(Map.of(), ClaimTimes.of(Map.of(claim, SECONDS)));
  }

  @Test
  void onlyTheTimeClaimsOfTheClaimSetAreIncluded() {
    final Map<String, Object> claims = new HashMap<>();
    claims.put("iss", "https://op.example.com");
    claims.put("iat", SECONDS);
    claims.put("exp", SECONDS + 3600);
    claims.put("auth_time", "not a time");
    claims.put("expires_in", 3600);

    assertEquals(Map.of("iat", TIME, "exp", "2026-09-17 14:04:16 UTC"), ClaimTimes.of(claims));
    // The claims are not changed
    assertEquals(SECONDS, claims.get("iat"));
    assertEquals(5, claims.size());
  }

  @Test
  void nestedTimeClaimsAreNotGivenATime() {
    final Map<String, Object> claims = Map.of(
        "address", Map.of("exp", SECONDS, "updated_at", SECONDS),
        "verified_claims", List.of(Map.of("iat", SECONDS)));

    assertEquals(Map.of(), ClaimTimes.of(claims));
  }

  @Test
  void noClaimsGiveNoTimes() {
    assertEquals(Map.of(), ClaimTimes.of(null));
    assertEquals(Map.of(), ClaimTimes.of(Map.of()));
  }

  @Test
  void aNullValueIsNotGivenATime() {
    final Map<String, Object> claims = new HashMap<>();
    claims.put("exp", null);

    assertEquals(Map.of(), ClaimTimes.of(claims));
  }

  static Stream<Arguments> wholeNumbers() {
    return Stream.of(
        Arguments.of(0, "1970-01-01 00:00:00 UTC"),
        Arguments.of(0L, "1970-01-01 00:00:00 UTC"),
        Arguments.of(1, "1970-01-01 00:00:01 UTC"),
        Arguments.of((short) 60, "1970-01-01 00:01:00 UTC"),
        Arguments.of((byte) 59, "1970-01-01 00:00:59 UTC"),
        Arguments.of((int) SECONDS, TIME),
        Arguments.of(SECONDS, TIME),
        Arguments.of(BigInteger.valueOf(SECONDS), TIME),
        Arguments.of(Integer.MAX_VALUE, "2038-01-19 03:14:07 UTC"),
        // 24-hour clock
        Arguments.of(1789688096L, "2026-09-17 23:34:56 UTC"),
        Arguments.of(253402300799L, "9999-12-31 23:59:59 UTC"),
        Arguments.of(253402300800L, "+10000-01-01 00:00:00 UTC"),
        // The latest time that can be computed
        Arguments.of(LATEST, "+999999999-12-31 23:59:59 UTC"),
        Arguments.of(BigInteger.valueOf(LATEST), "+999999999-12-31 23:59:59 UTC"));
  }

  @ParameterizedTest
  @MethodSource("wholeNumbers")
  void aWholeNumberZeroOrGreaterIsGivenATime(final Object value, final String expected) {
    assertEquals(Optional.of(expected), ClaimTimes.format(value));
  }

  static Stream<Object> notTimes() {
    return Stream.of(
        // Strings, also holding digits
        "1789650256", "", "2026-09-17T13:04:16Z",
        // Decimals, also without a fraction
        1789650256.0, 1789650256.5, 1789650256.5f, 0.0, new BigDecimal("1789650256"), new BigDecimal("1789650256.0"),
        // Negative numbers
        -1, -1L, (short) -1, (byte) -1, Integer.MIN_VALUE, Long.MIN_VALUE, BigInteger.valueOf(-1),
        // Out of range
        LATEST + 1, BigInteger.valueOf(LATEST + 1), Instant.MAX.getEpochSecond(), Long.MAX_VALUE,
        BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE), BigInteger.TWO.pow(100),
        // Other types
        true, false, Map.of("time", SECONDS), List.of(SECONDS), new Object());
  }

  @ParameterizedTest
  @MethodSource("notTimes")
  void otherValuesAreNotGivenATime(final Object value) {
    assertTrue(ClaimTimes.format(value).isEmpty(), () -> "Got a time for " + value);
    assertEquals(Map.of(), ClaimTimes.of(Map.of("exp", value)));
  }

  @Test
  void nullIsNotGivenATime() {
    assertTrue(ClaimTimes.format(null).isEmpty());
  }
}
