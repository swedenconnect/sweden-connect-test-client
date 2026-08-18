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
  private String logoutEndpoint;
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
