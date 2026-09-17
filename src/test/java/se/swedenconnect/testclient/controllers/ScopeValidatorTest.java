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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ScopeValidator} - in particular how UserInfo claims that could not be checked are reported.
 *
 * @author Martin Lindström
 */
class ScopeValidatorTest {

  private static final String EIDAS_IDENTITY = "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity";
  private static final String PRID = "https://id.swedenconnect.se/claim/prid";
  private static final String PRID_PERSISTENCE = "https://id.swedenconnect.se/claim/pridPersistence";
  private static final String EIDAS_PERSON_IDENTIFIER = "https://id.swedenconnect.se/claim/eidasPersonIdentifier";
  private static final String NATURAL_PERSON_NUMBER = "https://id.oidc.se/scope/naturalPersonNumber";
  private static final String NOT_CALLED = "UserInfo was not called";

  private static final Map<String, Object> ID_TOKEN = Map.of(PRID, "prid", PRID_PERSISTENCE, "A");

  @Test
  void aMandatoryUserInfoClaimIsMissingWhenUserInfoWasChecked() {
    final ScopeValidationResult result =
        ScopeValidator.validate(List.of(EIDAS_IDENTITY), ID_TOKEN, Map.of(), null).get(0);

    assertEquals(ScopeValidationResult.Status.MISSING, result.getStatus());
    assertTrue(result.getClaims().stream().noneMatch(ScopeValidationResult.ClaimValidationResult::isNotChecked));
  }

  @Test
  void aMandatoryUserInfoClaimIsNotCheckedWhenUserInfoWasNotChecked() {
    final ScopeValidationResult result =
        ScopeValidator.validate(List.of(EIDAS_IDENTITY), ID_TOKEN, null, NOT_CALLED).get(0);

    assertEquals(ScopeValidationResult.Status.NOT_CHECKED, result.getStatus());
    assertEquals("The claims expected from UserInfo were not checked, UserInfo was not called", result.getMessage());
    final ScopeValidationResult.ClaimValidationResult identifier = claim(result, EIDAS_PERSON_IDENTIFIER);
    assertFalse(identifier.isReceived());
    assertEquals(NOT_CALLED, identifier.getNotCheckedReason());
    // The ID token claims are checked as before
    assertTrue(claim(result, PRID).isReceived());
    assertNull(claim(result, PRID).getNotCheckedReason());
  }

  @Test
  void aMissingIdTokenClaimIsStillMissingWhenUserInfoWasNotChecked() {
    final ScopeValidationResult result =
        ScopeValidator.validate(List.of(EIDAS_IDENTITY), Map.of(PRID, "prid"), null, NOT_CALLED).get(0);

    assertEquals(ScopeValidationResult.Status.MISSING, result.getStatus());
    assertEquals("Missing claim(s): " + PRID_PERSISTENCE, result.getMessage());
    assertNull(claim(result, PRID_PERSISTENCE).getNotCheckedReason());
    assertEquals(NOT_CALLED, claim(result, EIDAS_PERSON_IDENTIFIER).getNotCheckedReason());
  }

  @Test
  void aUserInfoClaimReceivedInTheIdTokenIsReportedAsReceived() {
    final Map<String, Object> idToken = Map.of(PRID, "prid", PRID_PERSISTENCE, "A", EIDAS_PERSON_IDENTIFIER, "ES/SE/1");
    final ScopeValidationResult result =
        ScopeValidator.validate(List.of(EIDAS_IDENTITY), idToken, null, NOT_CALLED).get(0);

    assertEquals(ScopeValidationResult.Status.OK, result.getStatus());
    assertEquals("ID Token", claim(result, EIDAS_PERSON_IDENTIFIER).getReceivedIn());
    assertNull(claim(result, EIDAS_PERSON_IDENTIFIER).getNotCheckedReason());
  }

  @Test
  void idTokenClaimsAreNotAffectedByUserInfoNotBeingChecked() {
    final ScopeValidationResult result =
        ScopeValidator.validate(List.of(NATURAL_PERSON_NUMBER), Map.of(), null, NOT_CALLED).get(0);

    assertEquals(ScopeValidationResult.Status.MISSING, result.getStatus());
    assertTrue(result.getClaims().stream().noneMatch(ScopeValidationResult.ClaimValidationResult::isNotChecked));
  }

  @Test
  void scopesWithoutClaimsAreReportedAsBefore() {
    final List<ScopeValidationResult> results =
        ScopeValidator.validate(List.of("openid", "unknown"), Map.of(), null, NOT_CALLED);

    assertEquals(ScopeValidationResult.Status.NO_CLAIMS, results.get(0).getStatus());
    assertEquals(ScopeValidationResult.Status.UNKNOWN, results.get(1).getStatus());
  }

  private static ScopeValidationResult.ClaimValidationResult claim(final ScopeValidationResult result,
      final String claim) {
    return result.getClaims().stream().filter(c -> claim.equals(c.getClaim())).findFirst().orElseThrow();
  }
}
