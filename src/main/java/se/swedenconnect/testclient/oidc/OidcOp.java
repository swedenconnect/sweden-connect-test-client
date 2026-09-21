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

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import net.minidev.json.JSONObject;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Representation of an OpenID Provider that may be tested against - either statically configured or discovered
 * through OpenID Federation.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@AllArgsConstructor
@Builder
@NoArgsConstructor
@Getter
@Setter
public class OidcOp {

  /**
   * How an OP was configured.
   */
  public enum Source {
    /** The OP was configured in the application configuration. */
    STATIC,
    /** The OP was discovered and configured using OpenID Federation. */
    FEDERATION
  }

  /**
   * The Entity Identifier of the provider.
   */
  private String entityId;

  /**
   * The issuer identifier of the provider. For OP:s discovered through OpenID Federation this is the OP's entity
   * identifier, and for statically configured OP:s it is the {@code issuer} of the OP's metadata - read when the
   * metadata is fetched. A {@code null} value means that the issuer has not been established yet, and
   * {@link #getIssuer()} then falls back to the entity identifier.
   */
  @Nullable
  private String issuer;

  private String metadataEndpoint;
  private String authorizationEndpoint;
  private String tokenEndpoint;
  private String userInfoEndpoint;
  private String description;
  private String displayName;

  /** Tells how this OP was configured. */
  private Source source;

  /** For federation OP:s - the trust anchor that the OP was resolved under. */
  private String trustAnchor;

  /** For federation OP:s - the trust chain (serialized JWT:s), starting with the OP's entity configuration. */
  private List<String> trustChain;

  /** For federation OP:s - the metadata resulting from applying the federation metadata policies. */
  private JSONObject resolvedMetadata;

  /** The OP:s keys (if known). */
  private JWKSet jwks;

  /** For federation OP:s - the point in time when the resolved metadata expires. */
  private Instant expiresAt;

  /**
   * Gets the issuer identifier of the provider. If the issuer has not been established, the provider's entity
   * identifier is returned.
   *
   * @return the issuer identifier
   */
  @Nonnull
  public String getIssuer() {
    return Optional.ofNullable(this.issuer).orElseGet(this::getEntityId);
  }

  /**
   * Tells whether the provider's issuer identifier has been established, i.e., whether {@link #getIssuer()} returns
   * the issuer and not the entity identifier fallback.
   *
   * @return {@code true} if the issuer is known, and {@code false} otherwise
   */
  public boolean isIssuerKnown() {
    return this.issuer != null;
  }
}
