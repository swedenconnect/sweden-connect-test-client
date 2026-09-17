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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpHeaders;

/**
 * The outcome of the UserInfo call that the UserInfo claims of an authentication result come from.
 *
 * @author Martin Lindström
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResult {

  /** The outcome of the UserInfo call. */
  public enum Status {

    /** UserInfo was called and responded with a success status. */
    RECEIVED,

    /** No call was made to the UserInfo endpoint. */
    NOT_CALLED,

    /** The call failed - an error status was received, or no response at all. */
    FAILED
  }

  /** The outcome. */
  private Status status;

  /** Whether the call was made manually ("Send UserInfo Request") rather than automatically. */
  private boolean manual;

  /** The HTTP status of a failed call, or {@code null} if no response was received. */
  @JsonProperty("http_status")
  private Integer httpStatus;

  /** The {@code WWW-Authenticate} header of a failed call. */
  @JsonProperty("www_authenticate")
  private String wwwAuthenticate;

  /** The response body of a failed call. */
  private String body;

  /** Why no response was received, e.g., a network error. */
  private String error;

  /**
   * Creates the result for UserInfo claims that were received.
   *
   * @param manual whether the call was made manually
   * @return a {@link UserInfoResult}
   */
  @Nonnull
  public static UserInfoResult received(final boolean manual) {
    return UserInfoResult.builder().status(Status.RECEIVED).manual(manual).build();
  }

  /**
   * Creates the result for when UserInfo was not called.
   *
   * @return a {@link UserInfoResult}
   */
  @Nonnull
  public static UserInfoResult notCalled() {
    return UserInfoResult.builder().status(Status.NOT_CALLED).build();
  }

  /**
   * Creates the result for a failed call.
   *
   * @param exchange the failed call
   * @param manual whether the call was made manually
   * @return a {@link UserInfoResult}
   */
  @Nonnull
  public static UserInfoResult failed(@Nonnull final UserInfoExchange exchange, final boolean manual) {
    return UserInfoResult.builder()
        .status(Status.FAILED)
        .manual(manual)
        .httpStatus(exchange.getStatus())
        .wwwAuthenticate(exchange.getResponseHeader(HttpHeaders.WWW_AUTHENTICATE))
        .body(exchange.getBody() == null || exchange.getBody().isEmpty() ? null : exchange.getBody())
        .error(exchange.getError())
        .build();
  }

  /**
   * Tells why the UserInfo claims could not be checked.
   *
   * @return the reason, or {@code null} if the claims were received
   */
  @Nullable
  String notCheckedReason() {
    return switch (this.status) {
      case RECEIVED -> null;
      case NOT_CALLED -> "UserInfo was not called";
      case FAILED -> "the UserInfo call failed";
    };
  }
}
