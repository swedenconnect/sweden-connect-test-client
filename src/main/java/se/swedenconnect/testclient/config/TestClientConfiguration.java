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
package se.swedenconnect.testclient.config;

import jakarta.annotation.Nonnull;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import se.swedenconnect.testclient.saml.SamlFederation;

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

  private final SslBundles sslBundles;

  public TestClientConfiguration(@Nonnull final TestClientConfigurationProperties properties,
      @Nonnull final SslBundles sslBundles) {
    this.properties = properties;
    this.sslBundles = sslBundles;
  }

  @Bean
  SamlFederation samlFederation() throws Exception {
    if (this.properties.getSaml() != null) {
      return new SamlFederation(this.properties.getSaml().getFederation(), this.sslBundles);
    }
    else {
      return null;
    }
  }

}
