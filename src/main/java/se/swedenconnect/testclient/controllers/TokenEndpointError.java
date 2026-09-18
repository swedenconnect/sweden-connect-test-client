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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Why no tokens were received from the token endpoint - the token request could not be built, no response was
 * received, the token endpoint answered with an error status, or its success response could not be read.
 *
 * @author Martin Lindström
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenEndpointError {

  /** What went wrong. */
  private String message;

  /** The HTTP status of the response, or {@code null} if no response was received. */
  @JsonProperty("http_status")
  private Integer httpStatus;

  /** The {@code error} of an error response (RFC 6749, section 5.2), if present. */
  private String error;

  /** The {@code error_description} of an error response (RFC 6749, section 5.2), if present. */
  @JsonProperty("error_description")
  private String errorDescription;

  /** The raw response body, if a non-empty body was received. */
  private String body;

  /**
   * Gets the lines that the error is shown with on the authentication result.
   *
   * @return the lines
   */
  @Nonnull
  public List<String> toMessages() {
    final List<String> messages = new ArrayList<>();
    messages.add(this.message);
    if (this.httpStatus != null) {
      messages.add("HTTP status: %d".formatted(this.httpStatus));
    }
    if (this.error != null) {
      messages.add("error: %s".formatted(this.error));
    }
    if (this.errorDescription != null) {
      messages.add("error_description: %s".formatted(this.errorDescription));
    }
    if (this.body != null) {
      messages.add("Response body: %s".formatted(this.body));
    }
    return messages;
  }
}
