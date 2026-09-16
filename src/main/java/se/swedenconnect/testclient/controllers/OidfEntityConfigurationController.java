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

import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.oidc.federation.EntityConfigurationFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Publishes the OpenID Federation entity configurations for the test client's Relying Parties.
 * <p>
 * An RP has the entity identifier {@code <base-url>/<path-suffix>}, meaning that its entity configuration is published
 * at {@code <base-url>/<path-suffix>/.well-known/openid-federation}.
 * </p>
 *
 * @author Felix Hellman
 */
@RestController
@ConditionalOnProperty(value = "testclient.oidc.federation.enabled", havingValue = "true")
public class OidfEntityConfigurationController {

  /** The media type for entity statements. */
  public static final String ENTITY_STATEMENT_MEDIA_TYPE = "application/entity-statement+jwt";

  /** Mapper used to render the entity configuration as readable JSON when {@code plain=true} is requested. */
  private static final ObjectMapper OBJECT_MAPPER = JsonMapper.builder().build();

  /** The OIDC RP:s. */
  private final List<OidcRp> rps;

  /** The factory creating the entity configurations. */
  private final EntityConfigurationFactory factory;

  /**
   * Constructor.
   *
   * @param rps the OIDC RP:s
   * @param factory the entity configuration factory
   */
  public OidfEntityConfigurationController(
      @Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> rps,
      @Nonnull final EntityConfigurationFactory factory) {
    this.rps = rps;
    this.factory = factory;
  }

  /**
   * Returns the signed entity configuration for the given RP.
   *
   * @param rpSuffix the RP path suffix
   * @param plain if {@code true}, the entity configuration is returned as a readable JSON object containing the
   *     JWT's header and payload instead of the signed JWT
   * @return a signed entity statement, or its decoded header and payload if {@code plain} is {@code true}
   */
  @GetMapping(value = "/{rpSuffix}/.well-known/openid-federation")
  public ResponseEntity<String> getEntityConfiguration(
      @PathVariable("rpSuffix") @Nonnull final String rpSuffix,
      @RequestParam(value = "plain", required = false, defaultValue = "false") final boolean plain) {
    final OidcRp rp = this.rps.stream()
        .filter(r -> rpSuffix.equals(r.getPathSuffix()))
        .findFirst()
        .orElseThrow(() -> new NotFoundException("No OIDC RP with path suffix '%s'".formatted(rpSuffix)));

    final SignedJWT statement = this.factory.getEntityConfiguration(rp).getSignedStatement();

    if (plain) {
      try {
        final Map<String, Object> readable = new LinkedHashMap<>();
        readable.put("header", statement.getHeader().toJSONObject());
        readable.put("payload", statement.getJWTClaimsSet().toJSONObject());
        return ResponseEntity.ok()
            .header("Cache-Control", "no-cache, no-store")
            .contentType(MediaType.APPLICATION_JSON)
            .body(OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(readable));
      }
      catch (final java.text.ParseException e) {
        throw new IllegalStateException(
            "Failed to parse claims of the entity configuration for '%s'".formatted(rpSuffix), e);
      }
    }

    return ResponseEntity.ok()
        .header("Cache-Control", "no-cache, no-store")
        .contentType(MediaType.parseMediaType(ENTITY_STATEMENT_MEDIA_TYPE))
        .body(statement.serialize());
  }

}
