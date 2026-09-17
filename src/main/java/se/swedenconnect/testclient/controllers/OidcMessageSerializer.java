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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Produces the values of the user message and sign request extensions from their editable models.
 * <p>
 * The values are JSON objects represented as maps, which can be placed as claims in a JWT or serialized into a request
 * parameter. Only the members of the extensions are written - the UI settings of the models (placement, Base64 and JWT
 * settings) never are. Base64 encoding is applied to the produced value, and the models are never changed, so a value
 * that is produced for both the request URL and the request object is encoded once in each.
 * </p>
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
public class OidcMessageSerializer {

  /** The name of the user message request parameter and claim. */
  public static final String USER_MESSAGE = "https://id.oidc.se/param/userMessage";

  /** The name of the sign request request parameter and claim. */
  public static final String SIGN_REQUEST = "https://id.oidc.se/param/signRequest";

  /**
   * Gets the value of the user message extension.
   *
   * @param userMessage the user message model
   * @return the user message object
   */
  @Nonnull
  public static Map<String, Object> toUserMessage(@Nonnull final OidcMessageParameterModel userMessage) {
    return toMessage(userMessage, Boolean.TRUE.equals(userMessage.getB64Encode()));
  }

  /**
   * Gets the value of the sign request extension, i.e., the {@code tbs_data} (unless it is excluded) and the
   * {@code sign_message}.
   *
   * @param signRequest the sign request model
   * @return the sign request object
   */
  @Nonnull
  public static Map<String, Object> toSignRequest(@Nonnull final SignatureParameterModel signRequest) {
    final boolean encode = Boolean.TRUE.equals(signRequest.getB64Encode());
    final Map<String, Object> value = new LinkedHashMap<>();
    if (!Boolean.FALSE.equals(signRequest.getIncludeTbsData()) && signRequest.getTbsData() != null) {
      value.put("tbs_data", encode(signRequest.getTbsData(), encode));
    }
    if (signRequest.getSignMessage() != null) {
      value.put("sign_message", toMessage(signRequest.getSignMessage(), encode));
    }
    return value;
  }

  /**
   * Gets a message object - each language variant and the MIME type.
   *
   * @param message the message model
   * @param encode whether the message values are Base64-encoded
   * @return the message object
   */
  @Nonnull
  static Map<String, Object> toMessage(@Nonnull final OidcMessageParameterModel message, final boolean encode) {
    final Map<String, Object> value = new LinkedHashMap<>();
    put(value, "message#sv", message.getMessageSwedish(), encode);
    put(value, "message#en", message.getMessageEnglish(), encode);
    put(value, "message#de", message.getMessageGerman(), encode);
    put(value, "message#fr", message.getMessageFrench(), encode);
    put(value, "message#it", message.getMessageItalian(), encode);
    put(value, "message#es", message.getMessageSpanish(), encode);
    put(value, "message#xx", message.getMessageDummy(), encode);
    put(value, "message", message.getMessage(), encode);
    if (message.getMimeType() != null && !message.getMimeType().isBlank()) {
      value.put("mime_type", message.getMimeType());
    }
    return value;
  }

  private static void put(final Map<String, Object> target, final String name, @Nullable final String value,
      final boolean encode) {
    if (value != null) {
      target.put(name, encode(value, encode));
    }
  }

  private static String encode(final String value, final boolean encode) {
    return encode ? Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)) : value;
  }

  // Hidden constructor
  private OidcMessageSerializer() {
  }
}
