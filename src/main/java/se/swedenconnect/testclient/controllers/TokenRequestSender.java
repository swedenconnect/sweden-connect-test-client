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
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;
import java.util.Optional;

/**
 * Sends a token request to the token endpoint of an OP. Sending never throws - error statuses, network errors and
 * unreadable responses are reported in the returned {@link Result}.
 *
 * @author Martin Lindström
 */
@Slf4j
public class TokenRequestSender {

  private static final ObjectMapper objectMapper = JsonMapper.builder().build();

  /** The HTTP client. */
  private final RestClient client;

  /**
   * The outcome of a token request - either the token response or why it was not received.
   *
   * @param tokenResponse the token response (RFC 6749, section 5.1), or {@code null} if the request failed
   * @param error why the request failed, or {@code null} if the token response was received
   */
  public record Result(@Nullable Map<String, Object> tokenResponse, @Nullable TokenEndpointError error) {
  }

  /**
   * Constructor.
   *
   * @param client the HTTP client
   */
  public TokenRequestSender(@Nonnull final RestClient client) {
    this.client = client;
  }

  /**
   * Sends a token request.
   *
   * @param request the token request
   * @return the outcome
   */
  @Nonnull
  public Result send(@Nonnull final SentTokenRequest request) {
    final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    request.parameters().forEach(body::add);

    final ResponseEntity<String> response;
    try {
      response = this.client.post().uri(request.url())
          .headers(h -> request.headers().forEach(h::set))
          .body(body)
          .retrieve()
          // Error statuses are reported, not thrown
          .onStatus(status -> status.isError(), (req, errorResponse) -> {
          })
          .toEntity(String.class);
    }
    catch (final Exception e) {
      log.info("Token request to {} failed: {}", request.url(), e.getMessage());
      return new Result(null, TokenEndpointError.builder()
          .message("The token request to %s failed - no response was received: %s".formatted(request.url(),
              Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName())))
          .build());
    }

    final int status = response.getStatusCode().value();
    final String responseBody = Optional.ofNullable(response.getBody()).filter(b -> !b.isEmpty()).orElse(null);
    final Map<String, Object> json = readJsonObject(responseBody);

    if (!response.getStatusCode().is2xxSuccessful()) {
      log.info("Token request to {} was answered with status {}", request.url(), status);
      return new Result(null, TokenEndpointError.builder()
          .message("The token endpoint %s answered the token request with an error".formatted(request.url()))
          .httpStatus(status)
          .error(stringClaim(json, "error"))
          .errorDescription(stringClaim(json, "error_description"))
          .body(responseBody)
          .build());
    }
    if (json == null) {
      log.info("Token response from {} could not be read", request.url());
      return new Result(null, TokenEndpointError.builder()
          .message("The token endpoint %s answered the token request, but the response could not be read as a JSON"
              .formatted(request.url()) + " object")
          .httpStatus(status)
          .body(responseBody)
          .build());
    }
    return new Result(json, null);
  }

  @Nullable
  @SuppressWarnings("unchecked")
  private static Map<String, Object> readJsonObject(@Nullable final String body) {
    if (body == null) {
      return null;
    }
    try {
      final Object value = objectMapper.readValue(body, Object.class);
      return value instanceof Map ? (Map<String, Object>) value : null;
    }
    catch (final RuntimeException e) {
      return null;
    }
  }

  @Nullable
  private static String stringClaim(@Nullable final Map<String, Object> json, @Nonnull final String name) {
    return Optional.ofNullable(json).map(j -> j.get(name)).map(String::valueOf).orElse(null);
  }
}
