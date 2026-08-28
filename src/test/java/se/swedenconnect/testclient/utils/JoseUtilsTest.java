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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Tests for {@link se.swedenconnect.testclient.utils.JoseUtils}.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
class JoseUtilsTest {

  private static final JWTClaimsSet CLAIMS = new JWTClaimsSet.Builder().subject("test").build();

  @Test
  void signWithEcJwk() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
    Assertions.assertEquals(JWSAlgorithm.ES256, JoseUtils.signingAlgorithm(key));

    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JoseUtils.signingAlgorithm(key)).build(), CLAIMS);
    jwt.sign(JoseUtils.signer(key));
    Assertions.assertTrue(jwt.verify(new ECDSAVerifier(key.toPublicJWK())));
  }

  @Test
  void signWithRsaJwk() throws Exception {
    final RSAKey key = new RSAKeyGenerator(2048).keyID("rsa").generate();
    Assertions.assertEquals(JWSAlgorithm.RS256, JoseUtils.signingAlgorithm(key));

    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JoseUtils.signingAlgorithm(key)).build(), CLAIMS);
    jwt.sign(JoseUtils.signer(key));
    Assertions.assertTrue(jwt.verify(new RSASSAVerifier(key.toPublicJWK())));
  }

  @Test
  void signWithEcCredential() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_521).keyID("ec").generate();
    final PkiCredential credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
    Assertions.assertEquals(JWSAlgorithm.ES512, JoseUtils.signingAlgorithm(credential));

    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JoseUtils.signingAlgorithm(credential)).build(), CLAIMS);
    jwt.sign(JoseUtils.signer(credential));
    Assertions.assertTrue(jwt.verify(new ECDSAVerifier(key.toPublicJWK())));
  }

  @Test
  void signWithRsaCredential() throws Exception {
    final RSAKey key = new RSAKeyGenerator(2048).keyID("rsa").generate();
    final PkiCredential credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
    Assertions.assertEquals(JWSAlgorithm.RS256, JoseUtils.signingAlgorithm(credential));

    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JoseUtils.signingAlgorithm(credential)).build(), CLAIMS);
    jwt.sign(JoseUtils.signer(credential));
    Assertions.assertTrue(jwt.verify(new RSASSAVerifier(key.toPublicJWK())));
  }

  @Test
  void encryptWithEcJwk() throws Exception {
    final ECKey key = new ECKeyGenerator(Curve.P_256).keyID("ec").generate();
    final EncryptedJWT jwt = new EncryptedJWT(
        new JWEHeader.Builder(JoseUtils.keyEncryptionAlgorithm(key), EncryptionMethod.A256GCM).build(), CLAIMS);
    jwt.encrypt(JoseUtils.encrypter(key.toPublicJWK()));

    final EncryptedJWT parsed = EncryptedJWT.parse(jwt.serialize());
    parsed.decrypt(new ECDHDecrypter(key));
    Assertions.assertEquals("test", parsed.getJWTClaimsSet().getSubject());
  }

  @Test
  void encryptWithRsaJwk() throws Exception {
    final RSAKey key = new RSAKeyGenerator(2048).keyID("rsa").generate();
    final EncryptedJWT jwt = new EncryptedJWT(
        new JWEHeader.Builder(JoseUtils.keyEncryptionAlgorithm(key), EncryptionMethod.A256GCM).build(), CLAIMS);
    jwt.encrypt(JoseUtils.encrypter(key.toPublicJWK()));

    final EncryptedJWT parsed = EncryptedJWT.parse(jwt.serialize());
    parsed.decrypt(new RSADecrypter(key));
    Assertions.assertEquals("test", parsed.getJWTClaimsSet().getSubject());
  }

}
