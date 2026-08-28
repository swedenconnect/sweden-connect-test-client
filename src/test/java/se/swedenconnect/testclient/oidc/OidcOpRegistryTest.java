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
package se.swedenconnect.testclient.oidc;

import org.junit.jupiter.api.Test;
import se.swedenconnect.testclient.oidc.OidcOpRegistry.FederationOpState;
import se.swedenconnect.testclient.oidc.OidcOpRegistry.FederationOpStatus;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link OidcOpRegistry}, in particular that an OP that has once been configured from the federation is
 * kept.
 *
 * @author Felix Hellman
 */
class OidcOpRegistryTest {

  private static final String OP1 = "https://op1.example.com";

  private static final String OP2 = "https://op2.example.com";

  private final OidcOpRegistry registry = new OidcOpRegistry(List.of());

  @Test
  void keepsPreviouslyConfiguredOpsWhenTheFederationNoLongerListsThem() {
    this.registry.updateFederationOps(List.of(op(OP1), op(OP2)), Map.of(), List.of());
    this.registry.updateFederationOps(List.of(op(OP1)), Map.of(), List.of());

    assertEquals(List.of(OP1, OP2), this.registry.getFederationOps().stream()
        .map(OidcOp::getEntityId).sorted().toList());
    assertEquals(FederationOpState.OK, this.status(OP1).state());
    assertEquals(FederationOpState.NOT_LISTED, this.status(OP2).state());
    assertNotNull(this.status(OP2).lastResolved());
  }

  @Test
  void keepsAnOpThatCouldNotBeResolvedAndRecordsTheReason() {
    this.registry.updateFederationOps(List.of(op(OP1)), Map.of(), List.of());
    this.registry.updateFederationOps(List.of(), Map.of(OP1, "the trust anchor is down"),
        List.of("Resolution of %s failed".formatted(OP1)));

    assertTrue(this.registry.find(OP1).isPresent());
    assertEquals(FederationOpState.ERROR, this.status(OP1).state());
    assertEquals("the trust anchor is down", this.status(OP1).error());
  }

  @Test
  void recordsOpsThatHaveNeverBeenResolved() {
    this.registry.updateFederationOps(List.of(), Map.of(OP1, "no openid_provider metadata"), List.of());

    assertTrue(this.registry.getFederationOps().isEmpty());
    assertEquals(FederationOpState.ERROR, this.status(OP1).state());
    assertNull(this.status(OP1).lastResolved());
  }

  @Test
  void clearsTheErrorWhenTheOpIsResolvedAgain() {
    this.registry.updateFederationOps(List.of(), Map.of(OP1, "the trust anchor is down"), List.of());
    this.registry.updateFederationOps(List.of(op(OP1)), Map.of(), List.of());

    assertEquals(FederationOpState.OK, this.status(OP1).state());
    assertNull(this.status(OP1).error());
  }

  @Test
  void aFailedRefreshLeavesTheOpsAsTheyAre() {
    this.registry.updateFederationOps(List.of(op(OP1)), Map.of(), List.of());
    this.registry.federationRefreshFailed(List.of("Federation refresh failed"));

    assertEquals(List.of(OP1), this.registry.getFederationOps().stream().map(OidcOp::getEntityId).toList());
    assertEquals(FederationOpState.OK, this.status(OP1).state());
    assertEquals(List.of("Federation refresh failed"), this.registry.getFederationErrors());
  }

  private FederationOpStatus status(final String entityId) {
    return this.registry.getFederationOpStatus(entityId).orElseThrow();
  }

  private static OidcOp op(final String entityId) {
    return OidcOp.builder()
        .entityId(entityId)
        .source(OidcOp.Source.FEDERATION)
        .trustAnchor("https://ta.example.com")
        .build();
  }

}
