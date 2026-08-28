/*
 * Copyright 2025 Sweden Connect
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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Singular;

import java.util.List;

/**
 * Tells whether the claims that a requested scope is defined to deliver were actually received.
 *
 * @author Felix Hellman
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScopeValidationResult {

  /** The outcome for a scope. */
  public enum Status {

    /** All claims that the scope promises were received. */
    OK,

    /** A claim that the scope requires was not received. */
    MISSING,

    /** The claims were received, but not in the way the specification prescribes. */
    WARNING,

    /** The scope is not one of the scopes known by the test client. */
    UNKNOWN,

    /** The scope is known, but does not by itself deliver any claims. */
    NO_CLAIMS
  }

  /** The requested scope. */
  private String scope;

  /** The outcome for the scope. */
  private Status status;

  /** A message describing the outcome, if there is anything to point out. */
  private String message;

  /** The claims that the scope is defined to deliver. */
  @Singular
  private List<ClaimValidationResult> claims;

  /**
   * Tells whether a single claim of a scope was received.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ClaimValidationResult {

    /** The claim identifier. */
    private String claim;

    /** Where the claim is defined to be delivered, e.g. {@code ID Token}. */
    private String expectedLocation;

    /** How strongly the claim is required - {@code MANDATORY}, {@code ONE_OF} or {@code OPTIONAL}. */
    private String requirement;

    /** Whether the claim was received. */
    private boolean received;

    /** Where the claim was actually received, e.g. {@code ID Token, UserInfo}. */
    private String receivedIn;
  }
}
