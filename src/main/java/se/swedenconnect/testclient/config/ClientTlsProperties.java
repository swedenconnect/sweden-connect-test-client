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
package se.swedenconnect.testclient.config;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuration properties for client TLS settings.
 *
 * @author Martin Lindström
 */
public class ClientTlsProperties {

  public enum DefaultTlsTrustOption {
    JVM_TRUST,
    TRUST_ALL
  }

  /**
   * Whether we should skip hostname verification.
   */
  @Getter
  @Setter
  private boolean skipHostnameVerification = false;

  /**
   * An SSL bundle reference for the TLS trust. If not assigned, the trust is determined by {@code defaultTlsTrust}.
   */
  @Getter
  @Setter
  private String trustBundle;

  /**
   * Setting for how to configure TLS trust if no trust bundle is set.
   */
  @Getter
  @Setter
  private DefaultTlsTrustOption defaultTlsTrust = DefaultTlsTrustOption.JVM_TRUST;

  /**
   * Configures use of an HTTP proxy.
   */
  @Setter
  @Getter
  private HttpProxy httpProxy;

  /**
   * Configuration properties for an HTTP proxy.
   */
  public static class HttpProxy {

    /**
     * The proxy host.
     */
    @Setter
    @Getter
    private String host;

    /**
     * The proxy port.
     */
    @Setter
    @Getter
    private Integer port;

    /**
     * The proxy password (optional).
     */
    @Setter
    @Getter
    private String password;

    /**
     * The proxy username (optional).
     */
    @Setter
    @Getter
    private String userName;
  }

}
