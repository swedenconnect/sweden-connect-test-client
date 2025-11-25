package se.swedenconnect.testclient.oidc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@Builder
@NoArgsConstructor
@Getter
@Setter
public class OidcOp {
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
}
