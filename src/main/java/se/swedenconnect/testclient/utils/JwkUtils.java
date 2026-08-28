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
package se.swedenconnect.testclient.utils;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utilities for the JWK:s that the test client publishes.
 *
 * @author Felix Hellman
 */
public class JwkUtils {

  /**
   * Declares the intended use (and optionally the algorithm) of a JWK that is to be published. Entities that select
   * keys based on their declared use will otherwise not find any usable key in our metadata.
   *
   * @param jwk the JWK
   * @param keyUse the key use to declare
   * @param algorithm the algorithm to declare (may be {@code null})
   * @return a JWK declared for the given use
   */
  @Nonnull
  public static JWK declareUse(@Nonnull final JWK jwk, @Nonnull final KeyUse keyUse,
      @Nullable final Algorithm algorithm) {
    if (jwk.getKeyUse() != null && !keyUse.equals(jwk.getKeyUse())) {
      throw new IllegalArgumentException("The key %s is declared for %s use - expected %s"
          .formatted(jwk.getKeyID(), jwk.getKeyUse().identifier(), keyUse.identifier()));
    }
    if (keyUse.equals(jwk.getKeyUse()) && (algorithm == null || algorithm.equals(jwk.getAlgorithm()))) {
      return jwk;
    }
    final Map<String, Object> json = new LinkedHashMap<>(jwk.toJSONObject());
    json.put("use", keyUse.identifier());
    if (algorithm != null) {
      json.putIfAbsent("alg", algorithm.getName());
    }
    try {
      return JWK.parse(json);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException(
          "Failed to declare the key %s for %s use".formatted(jwk.getKeyID(), keyUse.identifier()), e);
    }
  }

  // Hidden constructor
  private JwkUtils() {
  }

}
