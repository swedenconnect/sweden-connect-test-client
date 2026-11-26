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

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the token exchange features are on when testclient.oidc.token-exchange.enabled is true.
 *
 * @author Simon Tardell
 */
@SpringBootTest(properties = {"testclient.oidc.federation.enabled=false", "testclient.oidc.token-exchange.enabled=true"})
@AutoConfigureMockMvc
@ActiveProfiles("test-oidf")
class TokenExchangeEnabledTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ApplicationContext context;

  @Autowired
  private ApplicationModel applicationModel;

  @Test
  void theUserInterfaceIsTold() {
    assertEquals(true, this.applicationModel.isTokenExchangeEnabled());
  }

  @Test
  void theControllerExistsOnlyWhenEnabled() {
    assertEquals(1, this.context.getBeanNamesForType(TokenExchangeController.class).length);
  }

  @Test
  void theEndpointsArePublishedOnlyWhenEnabled() throws Exception {
    this.mockMvc.perform(get("/oidc/authn/token-exchange/defaults"))
        .andExpect(status().isOk());
    this.mockMvc.perform(get("/oidc/protected-resources"))
        .andExpect(status().isOk());
  }
}
