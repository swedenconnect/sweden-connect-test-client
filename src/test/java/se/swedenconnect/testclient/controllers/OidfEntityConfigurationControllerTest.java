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

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the entity configurations are published and that the federation REST endpoints are wired.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test-oidf")
class OidfEntityConfigurationControllerTest {

  private static final String RP_ENTITY_ID = "https://client.example.com/testrp1";

  @Autowired
  private MockMvc mockMvc;

  @Test
  void publishesEntityConfiguration() throws Exception {
    final MvcResult result = this.mockMvc.perform(get("/testrp1/.well-known/openid-federation"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith("application/entity-statement+jwt"))
        .andReturn();

    final EntityStatement statement = EntityStatement.parse(result.getResponse().getContentAsString());
    statement.verifySignatureOfSelfStatement();

    final EntityStatementClaimsSet claims = statement.getClaimsSet();
    assertEquals(RP_ENTITY_ID, claims.getIssuerEntityID().getValue());
    assertEquals(RP_ENTITY_ID, claims.getSubjectEntityID().getValue());
    assertEquals(List.of("https://ta.example.com"),
        claims.getAuthorityHints().stream().map(a -> a.getValue()).toList());
    assertNotNull(claims.getMetadata(EntityType.OPENID_RELYING_PARTY));
    assertEquals("Sweden Connect", claims.getFederationEntityMetadata().getOrganizationName());
  }

  @Test
  void returnsNotFoundForUnknownRp() throws Exception {
    this.mockMvc.perform(get("/no-such-rp/.well-known/openid-federation"))
        .andExpect(status().isNotFound());
  }

  @Test
  void publishesFederationInfo() throws Exception {
    this.mockMvc.perform(get("/oidc/federation/info"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trust_anchors[0]").value("https://ta.example.com"))
        .andExpect(jsonPath("$.entities[0].entity_id").value(RP_ENTITY_ID))
        .andExpect(jsonPath("$.entities[0].entity_configuration_url")
            .value(RP_ENTITY_ID + "/.well-known/openid-federation"));
  }

}
