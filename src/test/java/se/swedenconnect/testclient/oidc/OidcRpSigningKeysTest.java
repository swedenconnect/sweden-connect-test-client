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
package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.credentials.TestCredentials;

import java.util.List;

/**
 * Tests for the keys that an OIDC RP publishes - a second, active, signing credential is published next to the
 * primary one.
 *
 * @author Martin Lindström
 */
class OidcRpSigningKeysTest {

  private static final String ENTITY_ID = "https://client.example.com/testrp1";

  private static final String METADATA = "{ \"client_name\" : \"Test RP\" }";

  @Test
  void anRpWithoutSigning2PublishesOneKey() throws Exception {
    final PkiCredential signing = TestCredentials.generate();

    final OidcRp rp = createRp(signing, null);

    Assertions.assertEquals(List.of(TestCredentials.keyId(signing)), keyIds(rp));
    Assertions.assertEquals(keyIds(rp), rp.getMetadata().getJWKSet().getKeys().stream().map(JWK::getKeyID).toList());
  }

  @Test
  void anRpWithSigning2PublishesBothKeys() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final PkiCredential signing2 = TestCredentials.generate();

    final OidcRp rp = createRp(signing, signing2);

    Assertions.assertEquals(
        List.of(TestCredentials.keyId(signing), TestCredentials.keyId(signing2)), keyIds(rp));
    // The embedded JWKS - which is also what the jwks_uri endpoint serves - holds both keys, declared for signature
    // use and without private key material
    Assertions.assertEquals(keyIds(rp), rp.getMetadata().getJWKSet().getKeys().stream().map(JWK::getKeyID).toList());
    rp.getJwkSet().getKeys().forEach(jwk -> {
      Assertions.assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
      Assertions.assertFalse(jwk.isPrivate());
    });
  }

  @Test
  void theKeysPublishedViaJwksUriAreTheSame() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final PkiCredential signing2 = TestCredentials.generate();

    final OidcRp embedded = createRp(signing, signing2, false);
    final OidcRp viaUrl = createRp(signing, signing2, true);

    Assertions.assertNull(viaUrl.getMetadata().getJWKSet());
    Assertions.assertEquals(ENTITY_ID + "/jwks", viaUrl.getMetadata().getJWKSetURI().toASCIIString());
    // The JWKS endpoint serves getJwkSet(), see OidcRpJwksController
    Assertions.assertEquals(embedded.getJwkSet().toJSONObject(), viaUrl.getJwkSet().toJSONObject());
  }

  private static List<String> keyIds(final OidcRp rp) {
    return rp.getJwkSet().getKeys().stream().map(JWK::getKeyID).toList();
  }

  private static OidcRp createRp(final PkiCredential signing, final PkiCredential signing2) throws Exception {
    return createRp(signing, signing2, false);
  }

  private static OidcRp createRp(final PkiCredential signing, final PkiCredential signing2,
      final boolean useJwksUrl) throws Exception {
    final ClientCredentials credentials =
        new ClientCredentials(signing, signing2, null, signing, null, signing, signing, signing);
    return new OidcRp(ENTITY_ID, "Test RP", "testrp1", credentials, METADATA, ENTITY_ID + "/redirect",
        useJwksUrl, ENTITY_ID + "/jwks", false);
  }

}
