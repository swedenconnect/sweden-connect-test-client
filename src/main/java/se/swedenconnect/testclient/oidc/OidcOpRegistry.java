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
import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.Getter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A registry holding the OpenID Providers that may be tested against - both those that are statically configured and
 * those that have been discovered using OpenID Federation.
 *
 * @author Felix Hellman
 */
public class OidcOpRegistry {

  /** The statically configured OP:s. */
  private final List<OidcOp> staticOps;

  /** The OP:s that have been configured using OpenID Federation - keyed by entity identifier. */
  private final Map<String, OidcOp> federationOps = new ConcurrentHashMap<>();

  /** The errors from the last federation refresh. */
  @Getter
  private volatile List<String> federationErrors = new CopyOnWriteArrayList<>();

  /** The status of the OP:s that have been discovered using OpenID Federation - keyed by entity identifier. */
  private final Map<String, FederationOpStatus> federationOpStatuses =
      Collections.synchronizedMap(new LinkedHashMap<>());

  /** The time when the OP:s were last refreshed from the federation. */
  @Getter
  private volatile Instant lastFederationRefresh;

  /**
   * Constructor.
   *
   * @param staticOps the statically configured OP:s
   */
  public OidcOpRegistry(@Nonnull final List<OidcOp> staticOps) {
    this.staticOps = List.copyOf(staticOps);
  }

  /**
   * Gets all OP:s. If an OP has been both statically configured and resolved from the federation, the federation
   * version is used.
   *
   * @return a list of OP:s
   */
  @Nonnull
  public List<OidcOp> getOps() {
    final Map<String, OidcOp> ops = new LinkedHashMap<>();
    this.staticOps.forEach(op -> ops.put(op.getEntityId(), op));
    ops.putAll(this.federationOps);
    return List.copyOf(ops.values());
  }

  /**
   * Gets the statically configured OP:s.
   *
   * @return a list of OP:s
   */
  @Nonnull
  public List<OidcOp> getStaticOps() {
    return this.staticOps;
  }

  /**
   * Gets the OP:s that have been configured using OpenID Federation.
   *
   * @return a list of OP:s
   */
  @Nonnull
  public List<OidcOp> getFederationOps() {
    return List.copyOf(this.federationOps.values());
  }

  /**
   * Finds the OP having the given entity identifier.
   *
   * @param entityId the entity identifier
   * @return an {@link Optional} {@link OidcOp}
   */
  @Nonnull
  public Optional<OidcOp> find(@Nonnull final String entityId) {
    return this.getOps().stream()
        .filter(op -> entityId.equals(op.getEntityId()))
        .findFirst();
  }

  /**
   * Finds the OP having the given entity identifier, or throws.
   *
   * @param entityId the entity identifier
   * @return an {@link OidcOp}
   */
  @Nonnull
  public OidcOp get(@Nonnull final String entityId) {
    return this.find(entityId)
        .orElseThrow(() -> new IllegalArgumentException("No such OpenID Provider found: " + entityId));
  }

  /**
   * Gets the status of all OP:s that have been discovered using OpenID Federation - including those that could not
   * be resolved during the latest refresh, and those that the federation no longer lists.
   *
   * @return the statuses, in the order that the OP:s were first discovered
   */
  @Nonnull
  public List<FederationOpStatus> getFederationOpStatuses() {
    synchronized (this.federationOpStatuses) {
      return List.copyOf(this.federationOpStatuses.values());
    }
  }

  /**
   * Gets the status of a federation OP.
   *
   * @param entityId the entity identifier
   * @return an {@link Optional} {@link FederationOpStatus}
   */
  @Nonnull
  public Optional<FederationOpStatus> getFederationOpStatus(@Nonnull final String entityId) {
    return Optional.ofNullable(this.federationOpStatuses.get(entityId));
  }

  /**
   * Registers, or updates, an OP that has been configured using OpenID Federation.
   *
   * @param op the OP
   */
  public void registerFederationOp(@Nonnull final OidcOp op) {
    this.federationOps.put(op.getEntityId(), op);
  }

  /**
   * Updates the registry with the outcome of a federation refresh.
   * <p>
   * An OP that has once been configured is never removed - if it could not be resolved this time around, or if the
   * federation no longer lists it, its previous configuration is kept and its status reflects what happened. This
   * way a temporarily misbehaving OP, or trust anchor, does not make the OP disappear from the test client.
   * </p>
   *
   * @param ops the OP:s that were successfully resolved
   * @param failures the OP:s that were discovered but could not be resolved (entity identifier to reason)
   * @param errors the errors that occurred during the refresh
   */
  public void updateFederationOps(@Nonnull final Collection<OidcOp> ops,
      @Nonnull final Map<String, String> failures, @Nonnull final List<String> errors) {

    final Instant now = Instant.now();

    synchronized (this.federationOpStatuses) {
      this.updateStatuses(ops, failures, now);
    }
    this.federationErrors = new CopyOnWriteArrayList<>(new ArrayList<>(errors));
    this.lastFederationRefresh = now;
  }

  private void updateStatuses(@Nonnull final Collection<OidcOp> ops, @Nonnull final Map<String, String> failures,
      @Nonnull final Instant now) {

    for (final OidcOp op : ops) {
      this.registerFederationOp(op);
      this.federationOpStatuses.put(op.getEntityId(),
          status(op.getEntityId(), this.federationOpStatuses.get(op.getEntityId()))
              .state(FederationOpState.OK)
              .lastResolved(now)
              .lastAttempt(now)
              .error(null)
              .build());
    }

    failures.forEach((entityId, reason) -> this.federationOpStatuses.put(entityId,
        status(entityId, this.federationOpStatuses.get(entityId))
            .state(FederationOpState.ERROR)
            .lastAttempt(now)
            .error(reason)
            .build()));

    // Everything that was known before, but that the federation did not list this time, is kept - but flagged.
    this.federationOpStatuses.replaceAll((entityId, previous) -> {
      if (ops.stream().anyMatch(op -> entityId.equals(op.getEntityId())) || failures.containsKey(entityId)) {
        return previous;
      }
      return previous.toBuilder()
          .state(FederationOpState.NOT_LISTED)
          .lastAttempt(now)
          .build();
    });
  }

  /**
   * Records that a federation refresh failed altogether. The OP:s that have been configured are kept as they are.
   *
   * @param errors the errors that occurred
   */
  public void federationRefreshFailed(@Nonnull final List<String> errors) {
    this.federationErrors = new CopyOnWriteArrayList<>(new ArrayList<>(errors));
    this.lastFederationRefresh = Instant.now();
  }

  @Nonnull
  private static FederationOpStatus.FederationOpStatusBuilder status(@Nonnull final String entityId,
      @Nullable final FederationOpStatus previous) {
    return Optional.ofNullable(previous)
        .map(FederationOpStatus::toBuilder)
        .orElseGet(() -> FederationOpStatus.builder()
            .entityId(entityId)
            .firstSeen(Instant.now()));
  }

  /**
   * The state of an OP that has been discovered using OpenID Federation.
   */
  public enum FederationOpState {

    /** The OP was resolved during the latest refresh. */
    OK,

    /** The OP is listed by the federation, but could not be resolved during the latest refresh. */
    ERROR,

    /** The OP is no longer listed by the federation - its previous configuration is kept. */
    NOT_LISTED
  }

  /**
   * The status of an OP that has been discovered using OpenID Federation.
   *
   * @param entityId the entity identifier of the OP
   * @param firstSeen when the OP was first discovered
   * @param lastResolved when the OP was last successfully resolved (null if it never was)
   * @param lastAttempt when the OP was last part of a refresh
   * @param state the state
   * @param error the reason why the OP could not be resolved (null if it could)
   */
  @Builder(toBuilder = true)
  public record FederationOpStatus(@Nonnull String entityId, @Nonnull Instant firstSeen,
                                   @Nullable Instant lastResolved, @Nonnull Instant lastAttempt,
                                   @Nonnull FederationOpState state, @Nullable String error) {
  }

}
