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

import com.nimbusds.jose.jwk.JWKSet;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.credentials.TestCredentials;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.client.ExpectedCount.manyTimes;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for the default audience of the request object and of the client assertion - both default to the issuer
 * identifier of the selected OP.
 *
 * @author Martin Lindström
 */
class OidcAudienceDefaultsTest {

  private static final String RP = "https://client.example.com/testrp1";
  private static final String OP = "https://op.example.com";
  private static final String METADATA_ENDPOINT = OP + "/.well-known/openid-configuration";
  private static final String JWKS_URI = OP + "/jwks";

  private static final String FED_OP = "https://fedop.example.com";

  private MockRestServiceServer server;
  private OIDCOPMetadataFetcher fetcher;
  private OidcOpRegistry registry;
  private OidcRp rp;

  @BeforeEach
  void setUp() throws Exception {
    final RestClient.Builder builder = RestClient.builder();
    this.server = MockRestServiceServer.bindTo(builder).ignoreExpectOrder(true).build();
    this.fetcher = new OIDCOPMetadataFetcher(builder.build());
    this.registry = Mockito.mock(OidcOpRegistry.class);
    this.rp = rp();
    this.server.expect(manyTimes(), requestTo(JWKS_URI))
        .andRespond(withSuccess(new JWKSet().toString(), MediaType.APPLICATION_JSON));
  }

  @Test
  void aStaticOpDefaultsToTheIssuerOfItsMetadata() {
    this.metadataIs(Map.of("issuer", OP + "/realm", "jwks_uri", JWKS_URI));
    this.register(staticOp());

    this.assertAudience(this.template(OP), OP + "/realm");
  }

  @Test
  void aStaticOpWhoseMetadataHasNoIssuerDefaultsToItsEntityIdentifier() {
    this.metadataIs(Map.of("jwks_uri", JWKS_URI));
    this.register(staticOp());

    this.assertAudience(this.template(OP), OP);
  }

  @Test
  void aStaticOpWhoseMetadataCanNotBeFetchedDefaultsToItsEntityIdentifier() {
    // The keys are known, so the metadata is only fetched for the issuer - and that fetch fails
    this.server.expect(manyTimes(), requestTo(METADATA_ENDPOINT)).andRespond(withStatus(HttpStatus.NOT_FOUND));
    final OidcOp op = staticOp();
    op.setJwks(new JWKSet());
    this.register(op);

    this.assertAudience(this.template(OP), OP);
  }

  @Test
  void aFederationOpDefaultsToItsEntityIdentifier() {
    this.register(federationOp());

    this.assertAudience(this.template(FED_OP), FED_OP);
  }

  @Test
  void selectingAnotherOpGivesTheDefaultsOfThatOp() {
    this.metadataIs(Map.of("issuer", OP + "/realm", "jwks_uri", JWKS_URI));
    this.register(staticOp(), federationOp());

    this.assertAudience(this.template(OP), OP + "/realm");
    this.assertAudience(this.template(FED_OP), FED_OP);
  }

  /**
   * Asserts that the audience of the request object and of the client assertion both are the expected issuer, and
   * that both rows are included and left editable.
   */
  private void assertAudience(final OIDCAuthnRequestParameterModel template, final String expected) {
    final ModelParameter requestObjectAud = template.getRequestObject().getAudience();
    Assertions.assertEquals(expected, requestObjectAud.getValue());
    Assertions.assertEquals(true, requestObjectAud.getValuePresent());

    final ModelParameter assertionAud = template.getTokenRequest().getAssertionAud();
    Assertions.assertEquals(expected, assertionAud.getValue());
    Assertions.assertEquals(true, assertionAud.getValuePresent());
  }

  private OIDCAuthnRequestParameterModel template(final String op) {
    final CredentialBundles bundles = Mockito.mock(CredentialBundles.class);
    Mockito.when(bundles.getRegisteredCredentials()).thenReturn(List.of());
    final OidcRestController controller = new OidcRestController(List.of(this.rp), this.registry,
        new MockHttpSession(), this.fetcher, bundles, null, Mockito.mock(RestClient.class));
    return controller.template(RP, op, new MockHttpSession());
  }

  private void register(final OidcOp... ops) {
    for (final OidcOp op : ops) {
      Mockito.when(this.registry.get(op.getEntityId())).thenReturn(op);
    }
  }

  private void metadataIs(final Map<String, Object> metadata) {
    this.server.expect(manyTimes(), requestTo(METADATA_ENDPOINT))
        .andRespond(withSuccess(new JSONObject(metadata).toJSONString(), MediaType.APPLICATION_JSON));
  }

  private static OidcOp staticOp() {
    return OidcOp.builder()
        .entityId(OP)
        .authorizationEndpoint(OP + "/authorize")
        .tokenEndpoint(OP + "/token")
        .metadataEndpoint(METADATA_ENDPOINT)
        .source(OidcOp.Source.STATIC)
        .build();
  }

  /**
   * An OP discovered through OpenID Federation - its issuer is its entity identifier and its keys are known, so no
   * metadata is fetched for it.
   */
  private static OidcOp federationOp() {
    return OidcOp.builder()
        .entityId(FED_OP)
        .issuer(FED_OP)
        .authorizationEndpoint(FED_OP + "/authorize")
        .tokenEndpoint(FED_OP + "/token")
        .resolvedMetadata(new JSONObject(Map.of("issuer", FED_OP)))
        .jwks(new JWKSet())
        .source(OidcOp.Source.FEDERATION)
        .build();
  }

  private static OidcRp rp() throws Exception {
    final PkiCredential signing = TestCredentials.generate();
    final ClientCredentials credentials =
        new ClientCredentials(signing, null, null, signing, null, signing, signing, signing);
    return new OidcRp(RP, "Test RP", "testrp1", credentials, "{ \"client_name\" : \"Test RP\" }",
        RP + "/redirect", false, RP + "/jwks", false);
  }
}
