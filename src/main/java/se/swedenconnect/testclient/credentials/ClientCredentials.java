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
package se.swedenconnect.testclient.credentials;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

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
  private final PkiCredential futureSigning;

  /** Encryption credential. */
  @Getter
  private final PkiCredential encryption;

  /** Previous encryption credential. */
  @Getter
  private final PkiCredential previousEncryption;

  /** Metadata signing credential. Also used for signing entity statements. */
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
   * @param futureSigning the future signing credential (used before key-rollover)
   * @param encryption the encryption credential
   * @param previousEncryption the previous encryption credential (used after key-rollover)
   * @param metadata the credential to use when signing SP metadata
   * @param defaultCredential the default credential, i.e., the credential to use if no specific credential is
   *     assigned
   * @param nonRegisteredCredential for testing credentials that have not been registered by the client
   * @throws IllegalArgumentException if a credential use is missing
   */
  public ClientCredentials(@Nullable final PkiCredential signing,
      @Nullable final PkiCredential futureSigning,
      @Nullable final PkiCredential encryption,
      @Nullable final PkiCredential previousEncryption,
      @Nullable final PkiCredential metadata,
      @Nullable final PkiCredential defaultCredential,
      @Nonnull final PkiCredential nonRegisteredCredential) throws IllegalArgumentException {
    this.signing = signing;
    this.futureSigning = futureSigning;
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
   * Creates a {@link ClientCredentials} object.
   *
   * @param credentialFactory the credential factory
   * @param properties the credential properties (if {@code null}, a {@code defaultCredential} must be supplied
   * @param defaultCredential the default credential, i.e., the credential to use if no specific credential is
   *     assigned
   * @param nonRegisteredCredential for testing non-registered credentials
   * @return a {@link ClientCredentials} object
   * @throws Exception if a credential cannot be created, or if a signing credential is missing
   */
  public static ClientCredentials create(@Nonnull final PkiCredentialFactory credentialFactory,
      @Nullable final ClientCredentialsProperties properties, @Nullable final PkiCredential defaultCredential,
      @Nullable final PkiCredential nonRegisteredCredential) throws Exception {
    if (properties == null) {
      return new ClientCredentials(null, null, null, null, null, defaultCredential, nonRegisteredCredential);
    }
    else {
      return new ClientCredentials(
          properties.getSigning() != null ? credentialFactory.createCredential(properties.getSigning()) : null,
          properties.getFutureSigning() != null
              ? credentialFactory.createCredential(properties.getFutureSigning())
              : null,
          properties.getEncryption() != null ? credentialFactory.createCredential(properties.getEncryption()) : null,
          properties.getPreviousEncryption() != null ? credentialFactory.createCredential(
              properties.getPreviousEncryption()) : null,
          properties.getMetadata() != null ? credentialFactory.createCredential(properties.getMetadata()) : null,
          defaultCredential,
          nonRegisteredCredential);
    }
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
    return Optional.ofNullable(this.metadata)
        .orElseGet(() -> Optional.ofNullable(this.defaultCredential)
            .orElseGet(this::getCredentialForSigning));
  }

}
