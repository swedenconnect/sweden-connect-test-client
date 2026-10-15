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
package se.swedenconnect.testclient.utils;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for {@link IdentifierSorting}.
 *
 * @author Martin Lindström
 */
class IdentifierSortingTest {

  private static final List<String> IDS = List.of(
      "https://idp.alpha.se", "https://beta.example.com", "https://idp.gamma.se", "https://alpha-beta.example.com",
      "https://other.example.com");

  @Test
  void keepsTheOrderWithoutPatterns() {
    assertEquals(IDS, sort(IDS, List.of()));
  }

  @Test
  void groupsByPatternInTheOrderThePatternsAreGiven() {
    assertEquals(List.of(
            "https://idp.gamma.se",
            "https://beta.example.com", "https://alpha-beta.example.com",
            "https://idp.alpha.se", "https://other.example.com"),
        sort(IDS, List.of("gamma", "beta")));
  }

  @Test
  void placesAnEntryUnderTheFirstPatternItMatches() {
    // alpha-beta matches both patterns, and is placed under "alpha", which is given first
    assertEquals(List.of(
            "https://idp.alpha.se", "https://alpha-beta.example.com",
            "https://beta.example.com",
            "https://idp.gamma.se", "https://other.example.com"),
        sort(IDS, List.of("alpha", "beta")));
  }

  @Test
  void matchesTextAnywhereIgnoringCase() {
    assertEquals(List.of(
            "https://idp.gamma.se", "https://idp.alpha.se",
            "https://beta.example.com", "https://alpha-beta.example.com", "https://other.example.com"),
        sort(IDS, List.of("GAMMA.SE", "IdP.")));
  }

  @Test
  void entriesMatchingNoPatternComeLastInTheirOriginalOrder() {
    assertEquals(List.of(
            "https://other.example.com",
            "https://idp.alpha.se", "https://beta.example.com", "https://idp.gamma.se",
            "https://alpha-beta.example.com"),
        sort(IDS, List.of("other", "no-such-entity")));
  }

  @Test
  void anEmptyPatternMatchesNothing() {
    assertEquals(List.of(
            "https://beta.example.com", "https://alpha-beta.example.com",
            "https://idp.alpha.se", "https://idp.gamma.se", "https://other.example.com"),
        sort(IDS, List.of("", "beta")));
  }

  @Test
  void handlesAnEmptyList() {
    assertEquals(List.of(), sort(List.of(), List.of("alpha")));
  }

  private static List<String> sort(final List<String> ids, final List<String> patterns) {
    return IdentifierSorting.sort(ids, Function.identity(), patterns);
  }

}
