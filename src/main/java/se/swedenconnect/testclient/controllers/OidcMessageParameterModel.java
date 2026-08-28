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
import com.nimbusds.jose.shaded.gson.annotations.Expose;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OidcMessageParameterModel {
  @JsonProperty("message#sv")
  @SerializedName("message#sv")
  private String messageSwedish;
  @JsonProperty("message#en")
  @SerializedName("message#en")
  private String messageEnglish;
  @JsonProperty("message#de")
  @SerializedName("message#de")
  private String messageGerman;
  @JsonProperty("message#fr")
  @SerializedName("message#fr")
  private String messageFrench;
  @JsonProperty("message#it")
  @SerializedName("message#it")
  private String messageItalian;
  @JsonProperty("message#es")
  @SerializedName("message#es")
  private String messageSpanish;
  @JsonProperty("message#xx")
  @SerializedName("message#xx")
  private String messageDummy;
  @JsonProperty("message")
  @SerializedName("message")
  private String message;
  @JsonProperty("mime_type")
  @SerializedName("mime_type")
  private String mimeType;
  private Boolean requestBody;
  private Boolean valuePresent;
  private Boolean b64Encode;
}
