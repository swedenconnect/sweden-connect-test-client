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
import jakarta.annotation.Nullable;
import net.shibboleth.shared.httpclient.HttpClientBuilder;
import net.shibboleth.shared.httpclient.HttpClientSupport;
import net.shibboleth.shared.httpclient.TLSSocketFactoryBuilder;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.util.StringUtils;
import se.swedenconnect.testclient.config.ClientTlsProperties;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Utilities working with {@link HttpClient HttpClient}.
 *
 * @author Martin Lindström
 */
public class HttpClientUtils {

  /**
   * Creates an {@link HttpClient} based on the supplied settings.
   *
   * @param properties the TLS settings (may be {@code null})
   * @param sslBundles the Spring SSL bunldes bean
   * @return an {@link HttpClient}
   * @throws Exception for errors creating the client
   */
  @Nonnull
  public static HttpClient createHttpClient(@Nullable final ClientTlsProperties properties,
      @Nonnull final SslBundles sslBundles) throws Exception {

    final ClientTlsProperties tlsSettings = Optional.ofNullable(properties).orElseGet(ClientTlsProperties::new);

    final TLSSocketFactoryBuilder tlsSocketFactoryBuilder = new TLSSocketFactoryBuilder();

    if (tlsSettings.getTrustBundle() != null) {
      tlsSocketFactoryBuilder.setTrustManagers(
          Arrays.asList(sslBundles.getBundle(tlsSettings.getTrustBundle()).getManagers().getTrustManagers()));
    }
    else if (ClientTlsProperties.DefaultTlsTrustOption.TRUST_ALL == tlsSettings.getDefaultTlsTrust()) {
      tlsSocketFactoryBuilder.setTrustManagers(List.of(HttpClientSupport.buildNoTrustX509TrustManager()));
    }

    tlsSocketFactoryBuilder.setHostnameVerifier(tlsSettings.isSkipHostnameVerification()
        ? new NoopHostnameVerifier() : new DefaultHostnameVerifier());

    final HttpClientBuilder builder = new HttpClientBuilder();
    builder.setUseSystemProperties(true);
    if (tlsSettings.getHttpProxy() != null) {
      if (tlsSettings.getHttpProxy().getHost() == null || tlsSettings.getHttpProxy().getPort() == null) {
        throw new IllegalArgumentException("Invalid HTTP proxy configuration");
      }
      builder.setConnectionProxyHost(tlsSettings.getHttpProxy().getHost());
      builder.setConnectionProxyPort(tlsSettings.getHttpProxy().getPort());
      if (StringUtils.hasText(tlsSettings.getHttpProxy().getUserName())) {
        builder.setConnectionProxyUsername(tlsSettings.getHttpProxy().getUserName());
      }
      if (StringUtils.hasText(tlsSettings.getHttpProxy().getPassword())) {
        builder.setConnectionProxyPassword(tlsSettings.getHttpProxy().getPassword());
      }
    }
    builder.setTLSSocketFactory(tlsSocketFactoryBuilder.build());

    return builder.buildClient();
  }

  // Hidden constructor
  private HttpClientUtils() {
  }

}
