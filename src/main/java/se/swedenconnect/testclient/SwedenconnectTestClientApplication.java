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
package se.swedenconnect.testclient;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ResourceLoader;
import se.swedenconnect.testclient.utils.PropertyToJWKSetConverter;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/**
 * Application main.
 *
 * @author Martin Lindström
 */
@SpringBootApplication
public class SwedenconnectTestClientApplication {

  public static void main(final String[] args) {
    SpringApplication.run(SwedenconnectTestClientApplication.class, args);
  }

  @Bean("openSAML")
  OpenSAMLInitializer openSAML() throws Exception {
    OpenSAMLInitializer.getInstance()
        .initialize(
            new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
            new OpenSAMLSecurityExtensionConfig());
    return OpenSAMLInitializer.getInstance();
  }

  /**
   * Creates a converter from a string to a {@link LocalizedString}.
   *
   * @return a LocalizedStringConverter bean
   */
  /**
   * Creates a converter from a string to a {@link JWKSet}.
   *
   * @param resourceLoader the resource loader
   * @return a JWKSet converter bean
   */
  @Bean
  @ConfigurationPropertiesBinding
  Converter<String, JWKSet> jwkSetConverter(@Nonnull final ResourceLoader resourceLoader) {
    return new PropertyToJWKSetConverter(resourceLoader);
  }

  @Bean
  @ConfigurationPropertiesBinding
  Converter<String, LocalizedString> localizedStringConverter() {
    return new Converter<>() {

      @Override
      public LocalizedString convert(@Nonnull final String source) {
        return new LocalizedString(source);
      }
    };
  }

}
