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

/**
 * The editable model for an OIDC authentication request. It is handed to the UI pre-filled for a given RP and OP,
 * freely edited by the operator, and posted back when the request is generated.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OIDCAuthnRequestParameterModel {
  private String op;
  private String rp;
  /** The scope. Its value is the scope sent in the request URL. */
  private ModelParameter scope;
  /**
   * The scope sent in the request object when the scope's "In Request Body" box is checked. If {@code null}, the value
   * of {@link #scope} is used, as in templates and requests exported before the scope had two lines.
   */
  private String requestBodyScope;
  /**
   * The mode of the request builder, {@code request} or {@code requestBody}. Only used by the UI, which carries it in
   * exported requests.
   */
  private String requestMode;
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
  /**
   * Whether UserInfo is called automatically after the token request. {@code null}, as in templates and requests
   * exported before the setting existed, means that it is called.
   */
  private Boolean callUserInfo;
  /**
   * The settings of the token request that is sent when the OP redirects back. {@code null}, as in requests exported
   * before the settings existed, means the defaults.
   */
  private TokenRequestParameterModel tokenRequest;
}
