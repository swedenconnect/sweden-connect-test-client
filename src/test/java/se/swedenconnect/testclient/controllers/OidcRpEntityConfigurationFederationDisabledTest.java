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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.List;

import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that no RP has an entity configuration when OpenID Federation support is disabled - also the ones that
 * have {@code create-entity-configuration} set (or defaulted) to {@code true}.
 *
 * @author Martin Lindström
 */
@SpringBootTest(properties = "testclient.oidc.federation.enabled=false")
@AutoConfigureMockMvc
@ActiveProfiles("test-oidf")
class OidcRpEntityConfigurationFederationDisabledTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  @Qualifier("testclient.oidc.RpList")
  private List<OidcRp> rps;

  @Test
  void noRpHasAnEntityConfiguration() throws Exception {
    assertEquals(2, this.rps.size());
    this.rps.forEach(rp -> assertFalse(rp.hasEntityConfiguration(), rp.getEntityId()));

    this.mockMvc.perform(get("/oidc/authn/info"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.rps[0].entity_configuration_url").value(nullValue()))
        .andExpect(jsonPath("$.rps[1].entity_configuration_url").value(nullValue()));

    this.mockMvc.perform(get("/oidc/rp/info"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].entity_configuration_url").value(nullValue()))
        .andExpect(jsonPath("$[1].entity_configuration_url").value(nullValue()));
  }

  @Test
  void noEntityConfigurationIsPublished() throws Exception {
    this.mockMvc.perform(get("/testrp1/.well-known/openid-federation"))
        .andExpect(status().isNotFound());
  }

}
