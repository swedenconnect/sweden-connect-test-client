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
package se.swedenconnect.testclient.controllers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Tells how a part of the authentication result was protected when it was delivered, i.e., whether it was signed
 * and/or encrypted, and with which algorithms.
 *
 * @author Felix Hellman
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProtectionInfo {

  /** Whether the object was signed. */
  private boolean signed;

  /** The JWS algorithm ({@code alg}) used, or {@code null} if the object was not signed. */
  private String signatureAlgorithm;

  /** The key identifier ({@code kid}) of the signing key. */
  private String signatureKeyId;

  /** The type header ({@code typ}) of the signed object. */
  private String signatureType;

  /** Whether the object was encrypted. */
  private boolean encrypted;

  /** The JWE key management algorithm ({@code alg}) used, or {@code null} if the object was not encrypted. */
  private String encryptionAlgorithm;

  /** The JWE content encryption method ({@code enc}) used. */
  private String encryptionMethod;

  /** The key identifier ({@code kid}) of the encryption key. */
  private String encryptionKeyId;

  /** The format the object was delivered in - {@code JSON}, {@code Plain JWT}, {@code Signed JWT} or
   * {@code Encrypted JWT}. */
  private String format;

  /** Any additional information, e.g., why the object could not be decrypted. */
  private String note;
}
