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

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * The editable model for the OIDC signature extension, i.e., the sign message and the data to be signed.
 * <p>
 * Apart from the sign request itself ({@code tbs_data} and {@code sign_message}) the model holds settings that decide
 * how the sign request is sent. None of them is sent; see {@link OidcMessageSerializer}.
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
public class SignatureParameterModel {
  /** The data to be signed. */
  private String tbsData;

  /** The sign message. Its MIME type is the one sent in the {@code sign_message} object. */
  private OidcMessageParameterModel signMessage;

  /** Whether the sign request is sent in the request URL. */
  private Boolean valuePresent;

  /** Whether the sign request is sent in the request object. */
  private Boolean requestBody;

  /** Whether the TBS data and the sign message values are Base64-encoded when sent. */
  private Boolean b64Encode;

  /** Whether {@code tbs_data} is sent. If {@code null}, it is sent. */
  private Boolean includeTbsData;

  /**
   * Whether the JWT carrying the sign request in the request URL is signed. If {@code false}, it is an unsecured JWT.
   * If {@code null}, it is signed.
   */
  private Boolean signJwt;

  /** The key ID of the key signing the JWT carrying the sign request in the request URL. */
  private String signKey;

  /**
   * Whether the JWT carrying the sign request in the request URL is encrypted, with the encryption key of the key
   * options.
   */
  private Boolean encryptJwt;

  @JsonIgnore
  public String getPreferredMessage() {
    if (Objects.nonNull(this.signMessage)) {
      return Stream.of(
          this.signMessage.getMessage(),
          this.signMessage.getMessageSwedish(),
          this.signMessage.getMessageEnglish(),
          this.signMessage.getMessageGerman(),
          this.signMessage.getMessageFrench(),
          this.signMessage.getMessageItalian(),
          this.signMessage.getMessageSpanish(),
          this.signMessage.getMessageDummy())
          .filter(Objects::nonNull)
          .findFirst()
          .orElse("");
    }
    return "";
  }
}
