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

import java.io.Serial;

/**
 * Tells that a token request could not be built from its settings, e.g., because the client assertion could not be
 * signed. The message says why, and is shown to the operator.
 *
 * @author Martin Lindström
 */
public class TokenRequestException extends Exception {

  @Serial
  private static final long serialVersionUID = 1L;

  /**
   * Constructor.
   *
   * @param message why the token request could not be built
   */
  public TokenRequestException(final String message) {
    super(message);
  }

  /**
   * Constructor.
   *
   * @param message why the token request could not be built
   * @param cause the cause
   */
  public TokenRequestException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
