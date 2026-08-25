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
package se.swedenconnect.testclient.oidc.federation;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;

import java.util.List;

/**
 * Keeps the set of federation OP:s in the {@link OidcOpRegistry} up to date.
 *
 * @author Felix Hellman
 */
@Slf4j
public class OidfOpRefresher {

  /** The federation service. */
  private final OidfService service;

  /** The registry to update. */
  private final OidcOpRegistry registry;

  /**
   * Constructor.
   *
   * @param service the federation service
   * @param registry the OP registry
   */
  public OidfOpRefresher(@Nonnull final OidfService service, @Nonnull final OidcOpRegistry registry) {
    this.service = service;
    this.registry = registry;
  }

  /**
   * Discovers and resolves all OP:s of the configured trust anchors and updates the registry. Invoked on a schedule -
   * no user interaction is involved in getting, or keeping, the OP:s configured.
   * <p>
   * OP:s that have been configured before are kept even if this refresh does not find them - see
   * {@link OidcOpRegistry#updateFederationOps(java.util.Collection, java.util.Map, List)}.
   * </p>
   *
   * @return the errors that occurred (empty if everything went well)
   */
  @Nonnull
  @Scheduled(initialDelayString = "${testclient.oidc.federation.initial-refresh-delay:2s}",
             fixedDelayString = "${testclient.oidc.federation.refresh-interval:10m}")
  public List<String> refresh() {
    log.debug("Refreshing OpenID Providers from the federation ...");
    try {
      final OidfService.FederationRefreshResult result = this.service.refreshOps();
      this.registry.updateFederationOps(result.ops(), result.failures(), result.errors());
      log.info("Federation refresh completed - {} OpenID Provider(s) resolved, {} configured in total, {} error(s)",
          result.ops().size(), this.registry.getFederationOps().size(), result.errors().size());
      return result.errors();
    }
    catch (final Exception e) {
      log.error("Federation refresh failed", e);
      final List<String> errors = List.of("Federation refresh failed: %s".formatted(e.getMessage()));
      this.registry.federationRefreshFailed(errors);
      return errors;
    }
  }

}
