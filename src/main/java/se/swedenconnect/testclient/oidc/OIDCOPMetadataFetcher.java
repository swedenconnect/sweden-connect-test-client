package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import net.minidev.json.JSONObject;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.util.Objects;

public class OIDCOPMetadataFetcher {
  private RestClient client;

  public OIDCOPMetadataFetcher(final RestClient client) {
    this.client = client;
  }

  /**
   * Gets the metadata for the given OP. For OP:s that have been configured using OpenID Federation the resolved
   * metadata (i.e., the metadata after the federation policies have been applied) is returned, and for other OP:s the
   * metadata is downloaded from the OP's metadata endpoint.
   *
   * @param oidcOp the OP
   * @return the OP metadata
   */
  public JSONObject getOPMetadata(final OidcOp oidcOp) {
    if (Objects.nonNull(oidcOp.getResolvedMetadata())) {
      return oidcOp.getResolvedMetadata();
    }
    return this.client.get().uri(oidcOp.getMetadataEndpoint()).retrieve()
        .toEntity(JSONObject.class)
        .getBody();
  }

  /**
   * Gets the keys for the given OP. For OP:s configured using OpenID Federation the keys from the resolved metadata
   * are used, and for other OP:s the keys are downloaded from the OP's {@code jwks_uri}.
   *
   * @param oidcOp the OP
   * @return the OP keys
   */
  public JWKSet getOPJWKS(@Nonnull final OidcOp oidcOp) {
    if (Objects.nonNull(oidcOp.getJwks())) {
      return oidcOp.getJwks();
    }
    final JSONObject metadata = this.getOPMetadata(oidcOp);
    final String jwksUri = metadata.getAsString("jwks_uri");
    if (Objects.isNull(jwksUri)) {
      throw new IllegalArgumentException("No keys available for OP %s".formatted(oidcOp.getEntityId()));
    }
    return this.getOPJWKS(jwksUri);
  }

  public JWKSet getOPJWKS(final String jwksUri) {
    final JSONObject body = this.client.get().uri(jwksUri)
        .retrieve()
        .body(JSONObject.class);
    try {
      return JWKSet.parse(body);
    } catch (final ParseException e) {
      throw new RuntimeException("Failed to parse JWKS", e);
    }
  }
}
