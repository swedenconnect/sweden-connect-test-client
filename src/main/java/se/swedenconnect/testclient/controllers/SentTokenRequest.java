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
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.Map;

/**
 * A token request as it is sent to the token endpoint of the OP (RFC 6749, section 4.1.3).
 *
 * @param method the HTTP method (always {@code POST})
 * @param url the token endpoint
 * @param headers the request headers, including any {@code Authorization} header
 * @param parameters the form parameters, in the order they are sent
 * @param clientAssertion the decoded client assertion, or {@code null} if no {@code client_assertion} was sent
 * @author Martin Lindström
 */
public record SentTokenRequest(
    @Nonnull String method,
    @Nonnull String url,
    @Nonnull Map<String, String> headers,
    @Nonnull Map<String, String> parameters,
    @JsonProperty("client_assertion") @Nullable ClientAssertion clientAssertion) {

  /**
   * The decoded client assertion that was sent. Either the header and claims are set, or - if the assertion could not
   * be decoded - the reason why.
   *
   * @param header the JOSE header
   * @param claims the claims
   * @param error why the assertion could not be decoded, or {@code null} if it was decoded
   */
  public record ClientAssertion(
      @Nullable Map<String, Object> header,
      @Nullable Map<String, Object> claims,
      @Nullable String error) {
  }
}
