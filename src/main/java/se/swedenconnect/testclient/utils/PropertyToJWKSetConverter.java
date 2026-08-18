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

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * Converts an application property string into a {@link JWKSet}. The property may either hold the JWK set inline (as
 * JSON) or point at a resource (for example {@code classpath:my-trust-anchor.jwks}).
 *
 * @author Martin Lindström
 */
public class PropertyToJWKSetConverter implements Converter<String, JWKSet> {

  /** For loading JWK sets given as resource locations. */
  private final ResourceLoader resourceLoader;

  /**
   * Default constructor.
   */
  public PropertyToJWKSetConverter() {
    this(new DefaultResourceLoader());
  }

  /**
   * Constructor.
   *
   * @param resourceLoader the resource loader to use when the property points at a resource
   */
  public PropertyToJWKSetConverter(@Nonnull final ResourceLoader resourceLoader) {
    this.resourceLoader = resourceLoader;
  }

  @Override
  public JWKSet convert(@Nonnull final String source) {
    try {
      if (this.isInline(source)) {
        return JWKSet.load(new ByteArrayInputStream(source.getBytes()));
      }
      try (final InputStream is = this.resourceLoader.getResource(source.trim()).getInputStream()) {
        return JWKSet.load(is);
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to instantiate JWKSet from " + source, e);
    }
  }

  private boolean isInline(@Nonnull final String property) {
    return property.trim().startsWith("{");
  }

}
