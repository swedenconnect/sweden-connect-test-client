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
package se.swedenconnect.testclient.saml;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.io.ByteArrayResource;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.testclient.config.ClientTlsProperties;
import se.swedenconnect.testclient.config.SamlProperties;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for the sorting of IdP:s in {@link SamlFederation}.
 *
 * @author Martin Lindström
 */
class SamlFederationTest {

  /** The IdP:s, in metadata order. */
  private static final List<String> IDPS = List.of(
      "https://idp.alpha.se", "https://beta.example.com", "https://idp.gamma.se", "https://alpha-beta.example.com",
      "https://other.example.com");

  @BeforeAll
  static void initOpenSaml() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
        new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
        new OpenSAMLSecurityExtensionConfig());
  }

  @Test
  void listsIdpsInMetadataOrderWithoutSorting() throws Exception {
    assertEquals(IDPS, idps(List.of()));
  }

  @Test
  void sortsEachIdpByItsOwnEntityId() throws Exception {
    // Before, the IdP checked against a pattern was the one at the position of the pattern, not the IdP being sorted
    assertEquals(List.of(
            "https://other.example.com",
            "https://idp.gamma.se",
            "https://idp.alpha.se", "https://beta.example.com", "https://alpha-beta.example.com"),
        idps(List.of("OTHER", "gamma")));
  }

  @Test
  void placesAnIdpUnderTheFirstPatternItMatches() throws Exception {
    assertEquals(List.of(
            "https://beta.example.com", "https://alpha-beta.example.com",
            "https://idp.alpha.se",
            "https://idp.gamma.se", "https://other.example.com"),
        idps(List.of("beta", "alpha")));
  }

  private static List<String> idps(final List<String> sorting) throws Exception {
    final SamlProperties.SamlFederationProperties properties = new SamlProperties.SamlFederationProperties();
    properties.setDescription("Test federation");
    final SamlProperties.SamlFederationProperties.FederationSource source =
        new SamlProperties.SamlFederationProperties.FederationSource();
    source.setMetadataLocation(new ByteArrayResource(metadata().getBytes(StandardCharsets.UTF_8)));
    properties.getSource().add(source);
    properties.getIdpSorting().addAll(sorting);

    final SamlFederation federation =
        new SamlFederation(properties, Mockito.mock(SslBundles.class), new ClientTlsProperties());
    return federation.getIdps().stream().map(EntityDescriptor::getEntityID).toList();
  }

  private static String metadata() {
    return """
        <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
        %s
        </md:EntitiesDescriptor>
        """.formatted(IDPS.stream().map(id -> """
          <md:EntityDescriptor entityID="%s">
            <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
              <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                  Location="%s/sso"/>
            </md:IDPSSODescriptor>
          </md:EntityDescriptor>
        """.formatted(id, id)).collect(Collectors.joining()));
  }

}
