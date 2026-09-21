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
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Optional;

/**
 * A single editable request parameter. Apart from its value it tells whether the parameter should be placed in the
 * request object rather than in the request URL, and whether it should be included at all.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class ModelParameter {
  private String value;
  private Boolean requestBody;
  private Boolean valuePresent;
  /**
   * The value sent in the request object when the parameter sends different values in the two locations, see
   * {@link AdvancedOptionsParamterModel#getAllowDifferentValues()}. {@code null}, as in templates and requests
   * exported before the setting existed, means that {@link #value} is sent in both locations.
   */
  private String requestBodyValue;

  /**
   * Creates a parameter that sends the same value in the request URL and in the request object.
   *
   * @param value the value
   * @param requestBody whether the parameter is placed in the request object
   * @param valuePresent whether the parameter is placed in the request URL
   */
  public ModelParameter(final String value, final Boolean requestBody, final Boolean valuePresent) {
    this(value, requestBody, valuePresent, null);
  }
}
