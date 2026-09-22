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

import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for how {@link OIDCOPMetadataFetcher} establishes the issuer identifier of an OP.
 *
 * @author Martin Lindström
 */
class OIDCOPMetadataFetcherTest {

  private static final String OP = "https://op.example.com";
  private static final String METADATA_ENDPOINT = OP + "/.well-known/openid-configuration";

  private MockRestServiceServer server;
  private OIDCOPMetadataFetcher fetcher;

  @BeforeEach
  void setUp() {
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).build();
    this.fetcher = new OIDCOPMetadataFetcher(builder.build());
  }

  @Test
  void theIssuerOfAStaticOpIsReadFromItsMetadata() {
    this.metadataIs(Map.of("issuer", OP + "/realm"));

    final OidcOp op = this.staticOp();
    Assertions.assertEquals(OP + "/realm", this.fetcher.getIssuer(op));
    this.server.verify();
    Assertions.assertTrue(op.isIssuerKnown());
    Assertions.assertEquals(OP + "/realm", op.getIssuer());
  }

  @Test
  void theIssuerIsReadOnce() {
    this.metadataIs(Map.of("issuer", OP + "/realm"));

    final OidcOp op = this.staticOp();
    Assertions.assertEquals(OP + "/realm", this.fetcher.getIssuer(op));
    // The metadata endpoint is only expected to be called once
    Assertions.assertEquals(OP + "/realm", this.fetcher.getIssuer(op));
    this.server.verify();
  }

  @Test
  void metadataWithoutAnIssuerGivesTheConfiguredEntityIdentifier() {
    this.metadataIs(Map.of("authorization_endpoint", OP + "/authorize"));

    final OidcOp op = this.staticOp();
    Assertions.assertEquals(OP, this.fetcher.getIssuer(op));
    // The fallback is not recorded - a later attempt may succeed
    Assertions.assertFalse(op.isIssuerKnown());
  }

  @Test
  void metadataThatCanNotBeFetchedGivesTheConfiguredEntityIdentifier() {
    this.server.expect(requestTo(METADATA_ENDPOINT)).andRespond(withStatus(HttpStatus.NOT_FOUND));

    final OidcOp op = this.staticOp();
    Assertions.assertEquals(OP, this.fetcher.getIssuer(op));
    Assertions.assertFalse(op.isIssuerKnown());
  }

  @Test
  void theIssuerOfAFederationOpIsItsEntityIdentifierAndNoMetadataIsFetched() {
    final OidcOp op = OidcOp.builder()
        .entityId(OP)
        .issuer(OP)
        .metadataEndpoint(OP + "/.well-known/openid-federation")
        .source(OidcOp.Source.FEDERATION)
        .build();

    Assertions.assertEquals(OP, this.fetcher.getIssuer(op));
    this.server.verify();
  }

  @Test
  void anOpWithoutAnIssuerReportsItsEntityIdentifier() {
    final OidcOp op = this.staticOp();
    Assertions.assertFalse(op.isIssuerKnown());
    Assertions.assertEquals(OP, op.getIssuer());
  }

  private OidcOp staticOp() {
    return OidcOp.builder()
        .entityId(OP)
        .metadataEndpoint(METADATA_ENDPOINT)
        .source(OidcOp.Source.STATIC)
        .build();
  }

  private void metadataIs(final Map<String, Object> metadata) {
    this.server.expect(requestTo(METADATA_ENDPOINT))
        .andRespond(withSuccess(new JSONObject(metadata).toJSONString(), MediaType.APPLICATION_JSON));
  }
}
