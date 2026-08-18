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
package se.swedenconnect.testclient.oidc.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Utility for verifying the signature of a JWT against a JWK set.
 *
 * @author Felix Hellman
 */
public class JwtVerifier {

  /** Factory for creating JWS verifiers. */
  private static final DefaultJWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();

  private JwtVerifier() {
  }

  /**
   * Verifies the signature of the supplied JWT.
   *
   * @param jwt the signed JWT
   * @param keys the keys to verify the signature against
   * @throws BadJOSEException if no key validates the signature
   */
  public static void verify(@Nonnull final SignedJWT jwt, @Nonnull final JWKSet keys) throws BadJOSEException {
    for (final JWK jwk : candidateKeys(jwt, keys)) {
      try {
        if (!(jwk instanceof final AsymmetricJWK asymmetricJWK)) {
          continue;
        }
        final Key key = asymmetricJWK.toPublicKey();
        final JWSVerifier verifier = verifierFactory.createJWSVerifier(jwt.getHeader(), key);
        if (jwt.verify(verifier)) {
          return;
        }
      }
      catch (final JOSEException e) {
        // Try the next key
      }
    }
    throw new BadJOSEException("Signature of JWT could not be validated - no matching key found");
  }

  @Nonnull
  private static List<JWK> candidateKeys(@Nonnull final SignedJWT jwt, @Nonnull final JWKSet keys) {
    final List<JWK> candidates = new ArrayList<>();
    Optional.ofNullable(jwt.getHeader().getKeyID())
        .map(keys::getKeyByKeyId)
        .ifPresent(candidates::add);
    keys.getKeys().stream()
        .filter(k -> !candidates.contains(k))
        .forEach(candidates::add);
    return candidates;
  }

}
