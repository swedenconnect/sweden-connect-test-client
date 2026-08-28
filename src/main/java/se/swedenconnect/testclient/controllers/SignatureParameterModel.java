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
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
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
  @SerializedName("tbs_data")
  private String tbsData;
  @SerializedName("sign_message")
  private OidcMessageParameterModel signMessage;
  private Boolean requestBody;
  private Boolean valuePresent;
  private Boolean b64Encode;

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
