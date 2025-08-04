/*
 * Copyright 2025 Sweden Connect
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
package se.swedenconnect.testclient.utils;

import jakarta.annotation.Nonnull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * A helper bean for constructing URL:s valid for the application.
 *
 * @author Martin Lindström
 */
@Component
public class UrlBuilderBean {

  /** The application base URL. */
  private final String baseUrl;

  /**
   * Constructor.
   *
   * @param baseUrl the base URL for the application. This includes the protocol, domain, and possibly the port and
   *     context path
   */
  public UrlBuilderBean(@Value("${testclient.base-url:#{null}}") final String baseUrl) {
    Assert.hasText(baseUrl, "testclient.base-url must be assigned");

    this.baseUrl = baseUrl.endsWith("/")
        ? baseUrl.substring(0, baseUrl.length() - 1)
        : baseUrl;
  }

  /**
   * Constructs a URL by appending the given path segments to the base URL.
   *
   * @param path one or more path segments to be appended to the base URL
   * @return the constructed URL as a String
   */
  public String buildUrl(@Nonnull final String... path) {
    if (path.length == 0) {
      return this.baseUrl;
    }
    final StringBuilder urlBuilder = new StringBuilder(this.baseUrl);
    for (final String p : path) {
      if (!p.startsWith("/")) {
        urlBuilder.append('/');
      }
      urlBuilder.append(p);
    }
    return urlBuilder.toString();
  }

}
