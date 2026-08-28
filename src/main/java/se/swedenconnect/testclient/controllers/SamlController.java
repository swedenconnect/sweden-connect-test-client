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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.time.Instant;

/**
 * SAML controller.
 *
 * @author Martin Lindström
 */
@Controller
public class SamlController {

  /** Session attribute name where we store the SAML response data. */
  public static final String SESSION_NAME_SAML_RESPONSE = "sctc.samlResponse";

  /** The base path for the assertion consumer service URL:s. */
  public static final String ASSERTION_CONSUMER_SERVICE_BASE_PATH = "/saml/acs";

  /**
   * Entry point where we receive SAML responses.
   *
   * @param request the HTTP servlet request
   * @param spSuffix the SP suffix
   * @param samlResponse the SAML response
   * @param relayState the relay state (may be {@code null})
   * @return a {@link ModelAndView} that redirects to the home view
   */
  @PostMapping(value = ASSERTION_CONSUMER_SERVICE_BASE_PATH + "/{spSuffix}")
  public ModelAndView processResponse(@Nonnull final HttpServletRequest request,
      @PathVariable("spSuffix") @Nonnull final String spSuffix,
      @RequestParam("SAMLResponse") @Nonnull final String samlResponse,
      @RequestParam(value = "RelayState", required = false) @Nullable final String relayState) {

    // TODO: check correct URL

    request.getSession().setAttribute(SESSION_NAME_SAML_RESPONSE,
        new SamlResponseData(samlResponse, relayState, request.getRequestURL().toString(), Instant.now()));

    return new ModelAndView("redirect:/");
  }

  /**
   * Model class for representing a SAML response.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class SamlResponseData {

    /** The SAML response. */
    @JsonProperty("saml_response")
    private String samlResponse;

    @JsonProperty("relay_state")
    private String relayState;

    @JsonProperty("receive_url")
    private String receiveUrl;

    @JsonProperty("receive_instant")
    private Instant receiveInstant;
  }

}
