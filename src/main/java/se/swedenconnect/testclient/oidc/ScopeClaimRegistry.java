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
package se.swedenconnect.testclient.oidc;

import jakarta.annotation.Nonnull;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The claims that the scopes of the Swedish OpenID Connect profile and the Sweden Connect eIDAS specifications are
 * defined to deliver.
 * <p>
 * The registry is used to tell whether an OP actually delivered what a requested scope promises. See
 * <a href="https://www.oidc.se/specifications/swedish-oidc-claims-specification-1_0.html">Claims and Scopes
 * Specification for the Swedish OpenID Connect Profile</a>,
 * <a href="https://www.oidc.se/specifications/oidc-signature-extension-1_1.html">Signature Extension for OpenID
 * Connect</a> and
 * <a href="https://docs.swedenconnect.se/technical-framework/latest/OpenID_Connect_Claims_and_Scopes_Specification.html">
 * OpenID Connect Claims and Scopes Specification for Sweden Connect</a>.
 *
 * @author Felix Hellman
 */
public final class ScopeClaimRegistry {

  /** Where a claim is defined to be delivered. */
  public enum Location {

    /** The claim is delivered in the ID Token. */
    ID_TOKEN("ID Token"),

    /** The claim is delivered from the UserInfo endpoint. */
    USER_INFO("UserInfo");

    private final String displayName;

    Location(final String displayName) {
      this.displayName = displayName;
    }

    /**
     * Gets a human readable name of the location.
     *
     * @return the display name
     */
    public String getDisplayName() {
      return this.displayName;
    }
  }

  /** How strongly a claim is required by the scope that requests it. */
  public enum Requirement {

    /** The claim must be delivered. */
    MANDATORY,

    /** Exactly one of the claims marked as {@code ONE_OF} within the scope must be delivered. */
    ONE_OF,

    /** The claim is voluntary. */
    OPTIONAL
  }

  /**
   * A claim that a scope is defined to deliver.
   *
   * @param name the claim identifier
   * @param location where the claim is defined to be delivered
   * @param requirement how strongly the claim is required
   */
  public record ScopeClaim(@Nonnull String name, @Nonnull Location location, @Nonnull Requirement requirement) {
  }

  private static final Map<String, List<ScopeClaim>> REGISTRY = Map.of(
      "openid", List.of(),

      "https://id.oidc.se/scope/naturalPersonInfo", List.of(
          new ScopeClaim("family_name", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("given_name", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("middle_name", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("name", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("birthdate", Location.USER_INFO, Requirement.OPTIONAL)),

      "https://id.oidc.se/scope/naturalPersonNumber", List.of(
          new ScopeClaim("https://id.oidc.se/claim/personalIdentityNumber", Location.ID_TOKEN, Requirement.ONE_OF),
          new ScopeClaim("https://id.oidc.se/claim/coordinationNumber", Location.ID_TOKEN, Requirement.ONE_OF)),

      "https://id.oidc.se/scope/naturalPersonOrgId", List.of(
          new ScopeClaim("https://id.oidc.se/claim/orgAffiliation", Location.ID_TOKEN, Requirement.MANDATORY),
          new ScopeClaim("name", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("https://id.oidc.se/claim/orgName", Location.USER_INFO, Requirement.OPTIONAL),
          new ScopeClaim("https://id.oidc.se/claim/orgNumber", Location.USER_INFO, Requirement.OPTIONAL)),

      "https://id.oidc.se/scope/sign", List.of(
          new ScopeClaim("https://id.oidc.se/claim/userSignature", Location.ID_TOKEN, Requirement.MANDATORY),
          new ScopeClaim("auth_time", Location.ID_TOKEN, Requirement.MANDATORY)),

      "https://id.oidc.se/scope/signApproval", List.of(),

      "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity", List.of(
          new ScopeClaim("https://id.swedenconnect.se/claim/prid", Location.ID_TOKEN, Requirement.MANDATORY),
          new ScopeClaim("https://id.swedenconnect.se/claim/pridPersistence", Location.ID_TOKEN,
              Requirement.MANDATORY),
          new ScopeClaim("https://id.swedenconnect.se/claim/eidasPersonIdentifier", Location.USER_INFO,
              Requirement.MANDATORY)),

      "https://id.swedenconnect.se/scope/eidasSwedishIdentity", List.of(
          new ScopeClaim("https://id.swedenconnect.se/claim/mappedPersonalIdentityNumber", Location.USER_INFO,
              Requirement.OPTIONAL),
          new ScopeClaim("https://id.swedenconnect.se/claim/mappedCoordinationNumber", Location.USER_INFO,
              Requirement.OPTIONAL),
          new ScopeClaim("https://id.swedenconnect.se/claim/identityBinding", Location.USER_INFO,
              Requirement.OPTIONAL))
  );

  /**
   * Gets the claims that the supplied scope is defined to deliver.
   *
   * @param scope the scope
   * @return the claims of the scope, or an empty {@link Optional} if the scope is not known by the test client
   */
  @Nonnull
  public static Optional<List<ScopeClaim>> getClaims(@Nonnull final String scope) {
    return Optional.ofNullable(REGISTRY.get(scope));
  }

  private ScopeClaimRegistry() {
  }
}
