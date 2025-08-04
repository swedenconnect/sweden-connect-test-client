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
package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * SAML controller.
 *
 * @author Martin Lindström
 */
@Controller
public class SamlController {

  /** The base path for the assertion consumer service URL:s. */
  public static final String ASSERTION_CONSUMER_SERVICE_BASE_PATH = "/saml/acs";

  @PostMapping(value = ASSERTION_CONSUMER_SERVICE_BASE_PATH + "/{sp}")
  public ModelAndView processResponse(@Nonnull final HttpServletRequest request,
      @Nonnull final HttpServletResponse response,
      @PathVariable("sp") @Nonnull final String sp,
      @RequestParam("SAMLResponse") @Nonnull final String samlResponse,
      @RequestParam(value = "RelayState", required = false) @Nullable final String relayState) {

    return null;
  }

}
