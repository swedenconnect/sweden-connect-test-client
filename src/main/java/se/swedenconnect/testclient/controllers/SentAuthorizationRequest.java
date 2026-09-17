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

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * An OIDC authentication request as it is sent to the authorization endpoint of the OP (OpenID Connect Core 1.0,
 * section 3.1.2.1).
 * <p>
 * With {@link Method#GET} the request parameters are in the query string of {@link #url()}, and {@link #parameters()}
 * is {@code null}. With {@link Method#POST} the url is the authorization endpoint as configured, and the parameters are
 * sent as a form body. The parameters are the same in both cases.
 * </p>
 *
 * @param method the HTTP method
 * @param url for GET the full request URL, for POST the authorization endpoint
 * @param parameters for POST the form parameters, for GET {@code null}
 * @author Martin Lindström
 */
public record SentAuthorizationRequest(
    @Nonnull Method method, @Nonnull String url, @Nullable Map<String, List<String>> parameters)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * The HTTP method used to send an authentication request.
   */
  public enum Method {
    /** The parameters are sent in the query string (OpenID Connect Core 1.0, section 13.1). */
    GET,
    /** The parameters are sent as a form body (OpenID Connect Core 1.0, section 13.2). */
    POST
  }
}
