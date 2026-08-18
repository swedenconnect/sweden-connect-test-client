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
package se.swedenconnect.testclient.oidc;

import jakarta.annotation.Nonnull;
import lombok.Getter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
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
   * Registers, or updates, an OP that has been configured using OpenID Federation.
   *
   * @param op the OP
   */
  public void registerFederationOp(@Nonnull final OidcOp op) {
    this.federationOps.put(op.getEntityId(), op);
  }

  /**
   * Replaces all federation OP:s with the supplied ones.
   *
   * @param ops the OP:s that were resolved
   * @param errors the errors that occurred during the refresh
   */
  public void updateFederationOps(@Nonnull final Collection<OidcOp> ops, @Nonnull final List<String> errors) {
    this.federationOps.keySet().removeIf(
        entityId -> ops.stream().noneMatch(op -> entityId.equals(op.getEntityId())));
    ops.forEach(this::registerFederationOp);
    this.federationErrors = new CopyOnWriteArrayList<>(new ArrayList<>(errors));
    this.lastFederationRefresh = Instant.now();
  }

}
