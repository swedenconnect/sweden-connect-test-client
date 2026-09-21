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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;

import java.util.List;

/**
 * Tests for the signing credentials of {@link ClientCredentials}.
 *
 * @author Martin Lindström
 */
class ClientCredentialsTest {

  @Test
  void withoutSigning2TheClientHasOneSigningCredential() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final PkiCredential other = TestCredentials.generate();

    final ClientCredentials credentials =
        new ClientCredentials(signing, null, null, other, null, null, other, other);

    Assertions.assertSame(signing, credentials.getCredentialForSigning());
    Assertions.assertNull(credentials.getSigning2());
    Assertions.assertEquals(List.of(signing), credentials.getCredentialsForSigning());
  }

  @Test
  void signing2IsAnAdditionalSigningCredential() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final PkiCredential signing2 = TestCredentials.generate();
    final PkiCredential other = TestCredentials.generate();

    final ClientCredentials credentials =
        new ClientCredentials(signing, signing2, null, other, null, null, other, other);

    // The primary signing credential is still the one used unless another key is selected
    Assertions.assertSame(signing, credentials.getCredentialForSigning());
    Assertions.assertEquals(List.of(signing, signing2), credentials.getCredentialsForSigning());
  }

  @Test
  void signing2IsAdditionalAlsoWhenTheDefaultCredentialSigns() throws Exception {
    final PkiCredential defaultCredential = TestCredentials.generate();
    final PkiCredential signing2 = TestCredentials.generate();

    final ClientCredentials credentials = new ClientCredentials(
        null, signing2, null, null, null, null, defaultCredential, defaultCredential);

    Assertions.assertSame(defaultCredential, credentials.getCredentialForSigning());
    Assertions.assertEquals(List.of(defaultCredential, signing2), credentials.getCredentialsForSigning());
  }

  @Test
  void theSameKeyMayNotBeAssignedTwice() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final PkiCredential sameKey = TestCredentials.copyOf(signing);

    final ClientCredentials credentials =
        new ClientCredentials(signing, sameKey, null, signing, null, null, signing, signing);

    final IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
        () -> credentials.assertDistinctSigningCredentials("https://rp.example.com"));
    Assertions.assertTrue(e.getMessage().contains("https://rp.example.com"), e.getMessage());
  }

  @Test
  void theDefaultCredentialMayNotBeAssignedAsSigning2() throws Exception {
    final PkiCredential defaultCredential = TestCredentials.generate();

    final ClientCredentials credentials = new ClientCredentials(null, TestCredentials.copyOf(defaultCredential),
        null, null, null, null, defaultCredential, defaultCredential);

    Assertions.assertThrows(IllegalArgumentException.class,
        () -> credentials.assertDistinctSigningCredentials("rp"));
  }

  @Test
  void distinctSigningCredentialsAreAccepted() throws Exception {
    final PkiCredential signing = TestCredentials.generate();

    Assertions.assertDoesNotThrow(() -> new ClientCredentials(
        signing, TestCredentials.generate(), null, signing, null, null, signing, signing)
        .assertDistinctSigningCredentials("rp"));
    Assertions.assertDoesNotThrow(() -> new ClientCredentials(
        signing, null, null, signing, null, null, signing, signing)
        .assertDistinctSigningCredentials("rp"));
  }

}
