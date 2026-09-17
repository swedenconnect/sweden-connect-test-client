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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Calls the UserInfo endpoint of an OP.
 * <p>
 * The access token is only sent in the {@code Authorization} header using the Bearer scheme (RFC 6750, section 2.1).
 * A call never throws - error statuses and network errors are reported in the returned {@link UserInfoExchange}.
 * </p>
 *
 * @author Martin Lindström
 */
@Slf4j
public class UserInfoCaller {

  /** The media types accepted from the UserInfo endpoint. */
  static final List<MediaType> ACCEPT = List.of(MediaType.APPLICATION_JSON, MediaType.valueOf("application/jwt"));

  /** The HTTP client. */
  private final RestClient client;

  /**
   * Constructor.
   *
   * @param client the HTTP client
   */
  public UserInfoCaller(@Nonnull final RestClient client) {
    this.client = client;
  }

  /**
   * Calls the UserInfo endpoint. A {@code POST} request has an empty body.
   *
   * @param endpoint the UserInfo endpoint
   * @param accessToken the access token - if {@code null} or empty, no {@code Authorization} header is sent
   * @param method the HTTP method, {@code GET} or {@code POST}
   * @param rp the RP (holding the keys needed to decrypt the response)
   * @return the call, including the parsed claims if the response has a success status
   */
  @Nonnull
  public UserInfoExchange call(@Nullable final String endpoint, @Nullable final String accessToken,
      @Nonnull final HttpMethod method, @Nonnull final OidcRp rp) {

    final Map<String, String> headers = new LinkedHashMap<>();
    headers.put(HttpHeaders.ACCEPT, MediaType.toString(ACCEPT));
    if (accessToken != null && !accessToken.isEmpty()) {
      headers.put(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(accessToken));
    }
    final UserInfoExchange.UserInfoExchangeBuilder exchange = UserInfoExchange.builder()
        .request(new UserInfoExchange.Request(method.name(), endpoint, headers));

    if (!HttpMethod.GET.equals(method) && !HttpMethod.POST.equals(method)) {
      return exchange.error("Unsupported HTTP method %s - use GET or POST".formatted(method.name())).build();
    }
    if (endpoint == null || endpoint.isBlank()) {
      return exchange.error("The OP has no UserInfo endpoint").build();
    }

    final ResponseEntity<String> response;
    try {
      response = this.client.method(method).uri(endpoint)
          .headers(h -> headers.forEach(h::set))
          .retrieve()
          // Error statuses are reported, not thrown
          .onStatus(status -> status.isError(), (request, errorResponse) -> {
          })
          .toEntity(String.class);
    }
    catch (final Exception e) {
      log.info("UserInfo call to {} failed: {}", endpoint, e.getMessage());
      return exchange.error("Failed to call %s: %s".formatted(endpoint,
          Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName()))).build();
    }

    final Map<String, List<String>> responseHeaders = new LinkedHashMap<>();
    response.getHeaders().forEach((name, values) -> responseHeaders.put(name, List.copyOf(values)));
    exchange.status(response.getStatusCode().value())
        .responseHeaders(responseHeaders)
        .body(response.getBody());

    if (response.getStatusCode().is2xxSuccessful()) {
      final OidcJwtParser.ProtectedJwt parsed =
          OidcJwtParser.parseUserInfo(response.getHeaders().getContentType(), response.getBody(), rp);
      exchange.claims(parsed.claims()).protection(parsed.protection());
    }
    else {
      log.info("UserInfo call to {} was answered with status {}", endpoint, response.getStatusCode().value());
    }
    return exchange.build();
  }
}
