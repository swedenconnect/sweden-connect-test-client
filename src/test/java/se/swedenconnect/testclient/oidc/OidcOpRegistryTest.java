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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link OidcOpRegistry}, in particular that an OP that has once been configured from the federation is
 * kept, and the order of the OP:s.
 *
 * @author Felix Hellman
 */
class OidcOpRegistryTest {

  private static final String OP1 = "https://op1.example.com";

  private static final String OP2 = "https://op2.example.com";

  private static final String OP3 = "https://op3.example.com";

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

  @Test
  void listsStaticOpsFirstThenFederationOpsInOrderOfFirstDiscovery() {
    final OidcOpRegistry registry = new OidcOpRegistry(List.of(staticOp("https://static.example.com")));
    final List<String> discovered = List.of(
        "https://op-d.example.com", "https://op-b.example.com", "https://op-a.example.com",
        "https://op-c.example.com", "https://op-e.example.com", "https://op-f.example.com");
    registry.updateFederationOps(discovered.stream().map(OidcOpRegistryTest::op).toList(), Map.of(), List.of());

    final List<String> expected = new ArrayList<>(List.of("https://static.example.com"));
    expected.addAll(discovered);
    assertEquals(expected, ids(registry.getOps()));
    assertEquals(expected, ids(registry.getSortedOps()));

    // A later refresh listing the OP:s in another order does not change the order
    registry.updateFederationOps(discovered.reversed().stream().map(OidcOpRegistryTest::op).toList(), Map.of(),
        List.of());
    assertEquals(expected, ids(registry.getOps()));
    assertEquals(discovered, ids(registry.getFederationOps()));
  }

  @Test
  void anOpThatIsResolvedLaterKeepsItsPlaceOfDiscovery() {
    this.registry.updateFederationOps(List.of(op(OP1)), Map.of(OP2, "the trust anchor is down"), List.of());
    this.registry.updateFederationOps(List.of(op(OP3)), Map.of(), List.of());
    this.registry.updateFederationOps(List.of(op(OP2)), Map.of(), List.of());

    assertEquals(List.of(OP1, OP2, OP3), ids(this.registry.getOps()));
  }

  @Test
  void anOpThatIsBothStaticAndFromTheFederationIsListedOnce() {
    final OidcOpRegistry registry = new OidcOpRegistry(
        List.of(staticOp(OP2), staticOp("https://static.example.com")), List.of("static"));
    registry.updateFederationOps(List.of(op(OP1), op(OP2)), Map.of(), List.of());

    assertEquals(List.of(OP2, "https://static.example.com", OP1), ids(registry.getOps()));
    assertEquals(OidcOp.Source.FEDERATION, registry.get(OP2).getSource());
    assertEquals(List.of("https://static.example.com", OP2, OP1), ids(registry.getSortedOps()));
  }

  @Test
  void sortsOpsByThePatternsIgnoringCase() {
    final OidcOpRegistry registry = new OidcOpRegistry(
        List.of(staticOp("https://static.example.com"), staticOp("https://op.TEST.se")),
        List.of("Test.SE", "op2", "op"));
    registry.updateFederationOps(List.of(op(OP3), op(OP1), op(OP2)), Map.of(), List.of());

    // op2 matches both "op2" and "op", and is placed under "op2"
    assertEquals(List.of("https://op.TEST.se", OP2, OP3, OP1, "https://static.example.com"),
        ids(registry.getSortedOps()));
    // The order of getOps() is not affected by the sorting
    assertEquals(List.of("https://static.example.com", "https://op.TEST.se", OP3, OP1, OP2),
        ids(registry.getOps()));
  }

  private FederationOpStatus status(final String entityId) {
    return this.registry.getFederationOpStatus(entityId).orElseThrow();
  }

  private static List<String> ids(final List<OidcOp> ops) {
    return ops.stream().map(OidcOp::getEntityId).toList();
  }

  private static OidcOp staticOp(final String entityId) {
    return OidcOp.builder()
        .entityId(entityId)
        .source(OidcOp.Source.STATIC)
        .build();
  }

  private static OidcOp op(final String entityId) {
    return OidcOp.builder()
        .entityId(entityId)
        .source(OidcOp.Source.FEDERATION)
        .trustAnchor("https://ta.example.com")
        .build();
  }

}
