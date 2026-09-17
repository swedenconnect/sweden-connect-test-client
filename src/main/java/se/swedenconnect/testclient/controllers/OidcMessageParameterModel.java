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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Model for a multilingual message, used for the user message and sign message extensions. Each language variant is
 * represented by its own field, and {@code message#xx} is a deliberately invalid variant for testing.
 * <p>
 * For the user message the model is the whole extension, so it also holds the placement boxes and the Base64 setting.
 * For the sign message these are held by {@link SignatureParameterModel}, and are not used here. None of them is sent;
 * see {@link OidcMessageSerializer}.
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
public class OidcMessageParameterModel {
  @JsonProperty("message#sv")
  private String messageSwedish;
  @JsonProperty("message#en")
  private String messageEnglish;
  @JsonProperty("message#de")
  private String messageGerman;
  @JsonProperty("message#fr")
  private String messageFrench;
  @JsonProperty("message#it")
  private String messageItalian;
  @JsonProperty("message#es")
  private String messageSpanish;
  @JsonProperty("message#xx")
  private String messageDummy;
  @JsonProperty("message")
  private String message;
  /** The MIME type of the message. If {@code null} or blank, no {@code mime_type} member is sent. */
  @JsonProperty("mime_type")
  private String mimeType;
  /** Whether the user message is sent in the request URL. */
  private Boolean valuePresent;
  /** Whether the user message is sent in the request object. */
  private Boolean requestBody;
  /** Whether the message values of the user message are Base64-encoded when sent. */
  private Boolean b64Encode;
}
