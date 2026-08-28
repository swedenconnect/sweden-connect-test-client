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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OIDCAuthnRequestParameterModel {
  private String op;
  private String rp;
  private ModelParameter scope;
  private ModelParameter clientId;
  private ModelParameter redirectUri;
  private ModelParameter acrValues;
  private Map<String, Object> claims;
  private Boolean claimInRequestBody;
  private RequestObjectParamterModel requestObject;
  private AdvancedOptionsParamterModel advanced;
  private KeyOptionsParameterModel keys;
  private OidcMessageParameterModel userMessage;
  private SignatureParameterModel signMessage;
}
