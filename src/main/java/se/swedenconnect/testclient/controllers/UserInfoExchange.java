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
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * A call to the UserInfo endpoint of an OP - the request as it was sent and what came back.
 *
 * @author Martin Lindström
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoExchange {

  /** The request as it was sent. */
  private Request request;

  /** The HTTP status of the response, or {@code null} if no response was received. */
  private Integer status;

  /** The response headers. */
  @JsonProperty("response_headers")
  private Map<String, List<String>> responseHeaders;

  /** The raw response body. */
  private String body;

  /** Why no response was received, e.g., a network error. {@code null} if a response was received. */
  private String error;

  /** The UserInfo claims - only present if the response has a success status. */
  private Map<String, Object> claims;

  /** How the UserInfo response was protected - only present if the response has a success status. */
  private ProtectionInfo protection;

  /**
   * Tells whether the call was successful, i.e., whether a response with a success (2xx) status was received. A
   * successful response is not necessarily readable.
   *
   * @return {@code true} if the call was successful
   */
  @JsonIgnore
  public boolean isSuccessful() {
    return this.error == null && this.status != null && this.status >= 200 && this.status < 300;
  }

  /**
   * Gets the first value of a response header.
   *
   * @param name the header name (case-insensitive)
   * @return the header value, or {@code null} if the response does not hold the header
   */
  @JsonIgnore
  public String getResponseHeader(final String name) {
    if (this.responseHeaders == null) {
      return null;
    }
    return this.responseHeaders.entrySet().stream()
        .filter(e -> e.getKey().equalsIgnoreCase(name))
        .flatMap(e -> e.getValue().stream())
        .findFirst()
        .orElse(null);
  }

  /**
   * A UserInfo request as it was sent.
   *
   * @param method the HTTP method
   * @param url the URL
   * @param headers the request headers
   */
  public record Request(String method, String url, Map<String, String> headers) {
  }
}
