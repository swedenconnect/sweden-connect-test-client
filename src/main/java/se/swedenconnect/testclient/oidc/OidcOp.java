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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import net.minidev.json.JSONObject;

import java.time.Instant;
import java.util.List;

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
}
