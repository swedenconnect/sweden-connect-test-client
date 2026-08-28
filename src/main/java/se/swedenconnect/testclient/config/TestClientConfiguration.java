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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.hc.client5.http.classic.HttpClient;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.testclient.controllers.ApplicationModel;
import se.swedenconnect.testclient.utils.HttpClientUtils;

import java.util.Optional;

/**
 * Configuration for the Sweden Connect Test Client configuration.
 *
 * @author Martin Lindström
 */
@Configuration
@DependsOn("openSAML")
@EnableConfigurationProperties(TestClientConfigurationProperties.class)
public class TestClientConfiguration {

  private final TestClientConfigurationProperties properties;
  private final PkiCredentialFactory credentialFactory;

  public TestClientConfiguration(@Nonnull final TestClientConfigurationProperties properties,
      @Nonnull final PkiCredentialFactory credentialFactory) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
  }

  @Bean
  SamlProperties samlProperties() {
    return this.properties.getSaml();
  }

  @Bean
  OidcProperties oidcProperties() {
    return this.properties.getOidc();
  }

  @Bean
  ClientTlsProperties clientTlsProperties() {
    return Optional.ofNullable(this.properties.getTls())
        .orElseGet(ClientTlsProperties::new);
  }

  @Bean("testclient.BaseUrl")
  @Nonnull
  String baseUrl() {
    return this.properties.getBaseUrl();
  }

  @Bean
  RestClient restClient(@Nonnull final RestClient.Builder builder, @Nonnull final SslBundles sslBundles,
      @Nonnull final ClientTlsProperties tlsProperties) throws Exception {

    final HttpClient httpClient = HttpClientUtils.createHttpClient(tlsProperties, sslBundles);
    return builder.requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient)).build();
  }

  @Bean("testclient.DefaultCredential")
  @Nullable
  PkiCredential defaultCredential() throws Exception {
    return this.properties.getDefaultCredential() != null
        ? this.credentialFactory.createCredential(this.properties.getDefaultCredential())
        : null;
  }

  @Bean("testclient.NonRegisteredCredential")
  @Nonnull
  PkiCredential nonRegisteredCredential() throws Exception {
    return this.credentialFactory.createCredential(this.properties.getNonRegisteredCredential());
  }

  @Bean
  ApplicationModel applicationModel() {
    final ApplicationModel model = new ApplicationModel();
    model.setSamlEnabled(Optional.ofNullable(this.properties.getSaml()).map(SamlProperties::isEnabled).orElse(false));
    model.setOidcEnabled(Optional.ofNullable(this.properties.getOidc()).map(OidcProperties::isEnabled).orElse(false));
    model.setOidfEnabled(model.isOidcEnabled()
        && Optional.ofNullable(this.properties.getOidc())
        .map(OidcProperties::getFederation)
        .map(OidfProperties::isEnabled)
        .orElse(false));

    // TODO: change
    model.setFederationName(
        Optional.ofNullable(this.properties.getSaml())
            .map(SamlProperties::getFederation)
            .map(SamlProperties.SamlFederationProperties::getDescription)
            .orElse("???"));

    return model;
  }

}
