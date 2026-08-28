package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
@NoArgsConstructor
public class OIDCResponse {
  private Map<String, Object> accessTokenClaims;
  /** The raw access token - it is not necessarily a JWT. */
  private String accessToken;
  private Map<String, Object> idTokenClaims;
  private Map<String, Object> userInfoClaims;
  private Map<String, Object> responseParameters;
  private Map<String, Object> requestParameters;
  private Map<String, Object> missingIdTokenClaims;
  private Map<String, Object> missingUserInfoClaims;
  private String authorizationRequest;
  private Map<String, Object> response;
  private List<String> errors;
  @JsonProperty("op_error")
  private Boolean opError;

}
