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
package se.swedenconnect.testclient.credentials;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Credentials for tests.
 *
 * @author Martin Lindström
 */
public class TestCredentials {

  /**
   * Generates a credential holding a fresh RSA key.
   *
   * @return a credential
   * @throws Exception for key generation errors
   */
  public static PkiCredential generate() throws Exception {
    final RSAKey key = new RSAKeyGenerator(2048).generate();
    return new BasicCredential(key.toPublicKey(), key.toPrivateKey());
  }

  /**
   * Creates another credential object holding the same key pair as the supplied credential.
   *
   * @param credential the credential to copy
   * @return a credential
   */
  public static PkiCredential copyOf(final PkiCredential credential) {
    return new BasicCredential(credential.getPublicKey(), credential.getPrivateKey());
  }

  /**
   * Gets a credential, including its certificate, from the bundled test keystore.
   *
   * @param alias the key alias, e.g. {@code rsa-2048}
   * @return a credential
   * @throws Exception if the key cannot be loaded
   */
  public static PkiCredential fromTestKeyStore(final String alias) throws Exception {
    final KeyStore keyStore = KeyStore.getInstance("JKS");
    try (final InputStream is = TestCredentials.class.getResourceAsStream("/test-client-credentials.jks")) {
      keyStore.load(is, "secret".toCharArray());
    }
    return new BasicCredential((X509Certificate) keyStore.getCertificate(alias),
        (PrivateKey) keyStore.getKey(alias, "secret".toCharArray()));
  }

  /**
   * Gets the key ID that a credential gets when it is turned into a JWK.
   *
   * @param credential the credential
   * @return the key ID
   */
  public static String keyId(final PkiCredential credential) {
    return new JwkTransformerFunction().serializable().apply(credential).getKeyID();
  }

  // Hidden constructor
  private TestCredentials() {
  }

}
