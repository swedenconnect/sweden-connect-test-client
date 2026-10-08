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

/**
 * The editable model for the request object of an OIDC authentication request - whether one should be created at
 * all, and whether it should be signed and/or encrypted.
 * <p>
 * The claims {@code iss}, {@code aud}, {@code iat} and {@code exp} of the request object are {@link ModelParameter}s
 * where {@code requestBody} tells whether the claim is included in the request object. An empty {@code iat} or
 * {@code exp} is filled in when the request is sent. A {@code null} claim is not included.
 * </p>
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RequestObjectParamterModel {
  /** The {@code iss} claim. */
  private ModelParameter issuer;

  /** The {@code aud} claim. */
  private ModelParameter audience;

  /** The {@code iat} claim. */
  private ModelParameter issuedAt;

  /** The {@code exp} claim. */
  private ModelParameter expiration;

  /** Whether the request object is signed. */
  private Boolean signRequest;

  /** Whether the request object is encrypted. */
  private Boolean encryptRequest;

  /** Whether the "Request object options" section is open. Only used by the UI. */
  private Boolean moduleEnabled;
}
