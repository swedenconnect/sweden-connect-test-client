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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Map;

/**
 * The result of a completed OIDC authentication - the tokens and claims that were received, how they were protected,
 * and any errors that occurred. This is the model that the UI displays.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
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
  private ProtectionInfo responseProtection;
  private ProtectionInfo idTokenProtection;
  private ProtectionInfo userInfoProtection;
  private Map<String, Object> missingIdTokenClaims;
  private Map<String, Object> missingUserInfoClaims;
  private List<ScopeValidationResult> scopeValidation;
  private String authorizationRequest;
  private Map<String, Object> response;
  private List<String> errors;
  @JsonProperty("op_error")
  private Boolean opError;

}
