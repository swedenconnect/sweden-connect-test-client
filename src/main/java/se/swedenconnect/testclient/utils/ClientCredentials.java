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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Representation of client credentials.
 *
 * @author Martin Lindström
 */
public class ClientCredentials {

  /** Signing credential. */
  @Getter
  private final PkiCredential signing;

  /** Optional future signing certificate. */
  @Getter
  private final X509Certificate futureSigningCertificate;

  /** Encryption credential. */
  @Getter
  private final PkiCredential encryption;

  /** Previous encryption credential. */
  @Getter
  private final PkiCredential previousEncryption;

  /** Metadata signing credential. */
  @Getter
  private final PkiCredential metadata;

  /** The default credential, i.e., the credential to use if no specific credential is assigned. */
  @Getter
  private final PkiCredential defaultCredential;

  /** For testing non-registered credentials. */
  @Getter
  private final PkiCredential nonRegisteredCredential;

  /**
   * Constructor.
   *
   * @param signing the signing credential
   * @param futureSigningCertificate the future signing certificate (used before key-rollover)
   * @param encryption the encryption credential
   * @param previousEncryption the previous encryption credential (used after key-rollover)
   * @param metadata the credential to use when signing SP metadata
   * @param defaultCredential the default credential, i.e., the credential to use if no specific credential is
   *     assigned
   * @param nonRegisteredCredential for testing credentials that have not been registered by the client
   */
  public ClientCredentials(@Nullable final PkiCredential signing,
      @Nullable final X509Certificate futureSigningCertificate,
      @Nullable final PkiCredential encryption,
      @Nullable final PkiCredential previousEncryption,
      @Nullable final PkiCredential metadata,
      @Nullable final PkiCredential defaultCredential,
      @Nonnull final PkiCredential nonRegisteredCredential) {
    this.signing = signing;
    this.futureSigningCertificate = futureSigningCertificate;
    this.encryption = encryption;
    this.previousEncryption = previousEncryption;
    this.metadata = metadata;
    this.defaultCredential = defaultCredential;
    if (this.signing == null && this.defaultCredential == null) {
      throw new IllegalArgumentException("Either signing or defaultCredential must be provided");
    }
    if (this.encryption == null && this.defaultCredential == null) {
      throw new IllegalArgumentException("Either encryption or defaultCredential must be provided");
    }
    this.nonRegisteredCredential = nonRegisteredCredential;
  }

  /**
   * Gets the credential to use for signing.
   *
   * @return the signing credential
   */
  @Nonnull
  public PkiCredential getCredentialForSigning() {
    return Optional.ofNullable(this.signing).orElseGet(() -> this.defaultCredential);
  }

  /**
   * Gets the credential(s) to use for encryption/decryption.
   *
   * @return a non-empty list of credentials
   */
  @Nonnull
  public List<PkiCredential> getCredentialsForEncryption() {
    final List<PkiCredential> credentials = new ArrayList<>();
    credentials.add(Optional.ofNullable(this.encryption).orElseGet(() -> this.defaultCredential));
    Optional.ofNullable(this.previousEncryption).ifPresent(credentials::add);
    return credentials;
  }

  /**
   * Gets the credential to use for metadata signing
   *
   * @return the metadata signing credential
   */
  @Nonnull
  public PkiCredential getCredentialForMetadataSigning() {
    return Optional.ofNullable(this.metadata).orElseGet(this::getCredentialForSigning);
  }

}
