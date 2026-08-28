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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * Utilities for creating JOSE signers and encrypters for both RSA and EC keys.
 *
 * @author Felix Hellman
 */
public class JoseUtils {

  /**
   * Determines the JWS algorithm to use for a key.
   *
   * @param jwk the key
   * @return the JWS algorithm ({@code RS256} for RSA keys, {@code ES256/ES384/ES512} for EC keys)
   */
  @Nonnull
  public static JWSAlgorithm signingAlgorithm(@Nonnull final JWK jwk) {
    if (KeyType.EC.equals(jwk.getKeyType())) {
      return ecSigningAlgorithm(jwk.toECKey().getCurve());
    }
    if (KeyType.RSA.equals(jwk.getKeyType())) {
      return JWSAlgorithm.RS256;
    }
    throw new IllegalArgumentException("Unsupported key type for signing: " + jwk.getKeyType());
  }

  /**
   * Determines the JWS algorithm to use for a credential.
   *
   * @param credential the credential
   * @return the JWS algorithm
   */
  @Nonnull
  public static JWSAlgorithm signingAlgorithm(@Nonnull final PkiCredential credential) {
    final PrivateKey key = credential.getPrivateKey();
    if (key instanceof final ECPrivateKey ecKey) {
      return ecSigningAlgorithm(Curve.forECParameterSpec(ecKey.getParams()));
    }
    if (key instanceof RSAPrivateKey) {
      return JWSAlgorithm.RS256;
    }
    throw new IllegalArgumentException("Unsupported key type for signing: " + key.getAlgorithm());
  }

  /**
   * Creates a signer for the supplied credential.
   *
   * @param credential the credential to sign with
   * @return a {@link JWSSigner}
   * @throws JOSEException for unsupported keys
   */
  @Nonnull
  public static JWSSigner signer(@Nonnull final PkiCredential credential) throws JOSEException {
    final PrivateKey key = credential.getPrivateKey();
    if (key instanceof final ECPrivateKey ecKey) {
      return new ECDSASigner(ecKey);
    }
    if (key instanceof final RSAPrivateKey rsaKey) {
      return new RSASSASigner(rsaKey);
    }
    throw new JOSEException("Unsupported key type for signing: " + key.getAlgorithm());
  }

  /**
   * Creates a signer for the supplied JWK. The key must hold its private part.
   *
   * @param jwk the key to sign with
   * @return a {@link JWSSigner}
   * @throws JOSEException for unsupported keys, or if the private part is missing
   */
  @Nonnull
  public static JWSSigner signer(@Nonnull final JWK jwk) throws JOSEException {
    if (KeyType.EC.equals(jwk.getKeyType())) {
      return new ECDSASigner(jwk.toECKey());
    }
    if (KeyType.RSA.equals(jwk.getKeyType())) {
      return new RSASSASigner(jwk.toRSAKey());
    }
    throw new JOSEException("Unsupported key type for signing: " + jwk.getKeyType());
  }

  /**
   * Determines the JWE key management algorithm to use for a key.
   *
   * @param jwk the key
   * @return {@code RSA-OAEP-256} for RSA keys and {@code ECDH-ES+A256KW} for EC keys
   */
  @Nonnull
  public static JWEAlgorithm keyEncryptionAlgorithm(@Nonnull final JWK jwk) {
    if (KeyType.EC.equals(jwk.getKeyType())) {
      return JWEAlgorithm.ECDH_ES_A256KW;
    }
    if (KeyType.RSA.equals(jwk.getKeyType())) {
      return JWEAlgorithm.RSA_OAEP_256;
    }
    throw new IllegalArgumentException("Unsupported key type for encryption: " + jwk.getKeyType());
  }

  /**
   * Creates an encrypter for the supplied JWK (public part is enough).
   *
   * @param jwk the key to encrypt for
   * @return a {@link JWEEncrypter}
   * @throws JOSEException for unsupported keys
   */
  @Nonnull
  public static JWEEncrypter encrypter(@Nonnull final JWK jwk) throws JOSEException {
    if (KeyType.EC.equals(jwk.getKeyType())) {
      return new ECDHEncrypter(jwk.toECKey().toECPublicKey());
    }
    if (KeyType.RSA.equals(jwk.getKeyType())) {
      return new RSAEncrypter(jwk.toRSAKey().toRSAPublicKey());
    }
    throw new JOSEException("Unsupported key type for encryption: " + jwk.getKeyType());
  }

  /**
   * Creates a decrypter for the supplied credential.
   *
   * @param credential the credential holding the private key to decrypt with
   * @return a {@link JWEDecrypter}
   * @throws JOSEException for unsupported keys
   */
  @Nonnull
  public static JWEDecrypter decrypter(@Nonnull final PkiCredential credential) throws JOSEException {
    final PrivateKey key = credential.getPrivateKey();
    if (key instanceof final ECPrivateKey ecKey) {
      return new ECDHDecrypter(ecKey);
    }
    if (key instanceof final RSAPrivateKey rsaKey) {
      return new RSADecrypter(rsaKey);
    }
    throw new JOSEException("Unsupported key type for decryption: " + key.getAlgorithm());
  }

  @Nonnull
  private static JWSAlgorithm ecSigningAlgorithm(final Curve curve) {
    if (Curve.P_384.equals(curve)) {
      return JWSAlgorithm.ES384;
    }
    if (Curve.P_521.equals(curve)) {
      return JWSAlgorithm.ES512;
    }
    return JWSAlgorithm.ES256;
  }

  // Hidden constructor
  private JoseUtils() {
  }

}
