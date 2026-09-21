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

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;

/**
 * Configuration properties for client credentials.
 *
 * @author Martin Lindström
 */
public class ClientCredentialsProperties {

  /**
   * The signing credential. If not set, the default credential must be assigned.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties signing;

  /**
   * An additional, active, signing credential. Affects OIDC RP:s only, where it is published as a registered key of
   * the RP and is selectable under "Key options". May not be the same key as {@link #signing}.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties signing2;

  /**
   * Set in advance before rolling the signing credential ...
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties futureSigning;

  /**
   * The encryption credential. If not set, the default credential must be assigned.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties encryption;

  /**
   * The previous encryption credential. Must be set after the encryption key has been updated.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties previousEncryption;

  /**
   * The credential to use for (federation) metadata signing.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties metadata;

}
