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

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.List;

/**
 * Publishes the JWK set of an RP - used when the RP declares {@code use-jwks-url: true}, meaning that its keys are
 * published via {@code jwks_uri} rather than embedded in its metadata.
 * <p>
 * An RP's JWK set is published at {@code <base-url>/<path-suffix>/jwks}.
 * </p>
 *
 * @author Per Fredrik Plars
 */
@RestController
@ConditionalOnProperty(value = "testclient.oidc.enabled", havingValue = "true")
public class OidcRpJwksController {

  /** The OIDC RP:s. */
  private final List<OidcRp> rps;

  /**
   * Constructor.
   *
   * @param rps the OIDC RP:s
   */
  public OidcRpJwksController(@Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> rps) {
    this.rps = rps;
  }

  /**
   * Returns the JWK set for the given RP.
   *
   * @param rpSuffix the RP path suffix
   * @return the JWK set
   */
  @GetMapping(value = "/{rpSuffix}/jwks")
  public JSONObject getJwks(@PathVariable("rpSuffix") @Nonnull final String rpSuffix) {
    final JWKSet jwkSet = this.rps.stream()
        .filter(r -> rpSuffix.equals(r.getPathSuffix()))
        .findFirst()
        .orElseThrow(() -> new NotFoundException("No OIDC RP with path suffix '%s'".formatted(rpSuffix)))
        .getJwkSet();
    return new JSONObject(jwkSet.toJSONObject());
  }

}
