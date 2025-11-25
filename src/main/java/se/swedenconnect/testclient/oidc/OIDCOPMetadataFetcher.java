package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import org.springframework.web.client.RestClient;

import java.text.ParseException;

public class OIDCOPMetadataFetcher {
  private RestClient client;

  public OIDCOPMetadataFetcher(final RestClient client) {
    this.client = client;
  }

  public JSONObject getOPMetadata(final OidcOp oidcOp) {
    return this.client.get().uri(oidcOp.getMetadataEndpoint()).retrieve()
        .toEntity(JSONObject.class)
        .getBody();
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
