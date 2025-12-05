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

import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

/**
 * The main controller - the start page.
 *
 * @author Martin Lindström
 */
@Controller
public class MainController {

  private final ApplicationModel applicationInfo;
  private final ServletContext context;

  public MainController(final ApplicationModel applicationModel,
                        final ServletContext context) {
    this.applicationInfo = applicationModel;
    this.context = context;
  }

  @GetMapping("/")
  public ModelAndView home(@Nonnull final HttpServletRequest request) {
    final ModelAndView view = new ModelAndView("sc-client");
    view.addObject("applicationInfo", this.applicationInfo);

    final HttpSession session = request.getSession();
    Optional.ofNullable(session.getAttribute(SamlController.SESSION_NAME_SAML_RESPONSE))
        .ifPresent(data -> {
          view.addObject("samlResponseData", data);
          session.removeAttribute(SamlController.SESSION_NAME_SAML_RESPONSE);
        });

    Optional.ofNullable(session.getAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE))
        .ifPresent(data -> {
          view.addObject("oidcResponseData", data);
          session.removeAttribute(OidcController.SESSION_NAME_OIDC_RESPONSE);
        });
    if (!context.getContextPath().isBlank() || !context.getContextPath().equals("/")) {
      view.addObject("contextPath", context.getContextPath());
    }

    return view;
  }

}
