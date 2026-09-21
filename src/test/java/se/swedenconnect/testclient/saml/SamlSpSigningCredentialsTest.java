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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.config.SamlSpProperties;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.credentials.TestCredentials;

import java.util.List;

/**
 * Tests that the additional signing credential of a client, which is an OIDC feature, does not affect a SAML SP.
 *
 * @author Martin Lindström
 */
class SamlSpSigningCredentialsTest {

  private static final String ENTITY_ID = "https://sp.example.com";

  @BeforeAll
  static void initOpenSaml() throws Exception {
    OpenSAMLInitializer.getInstance().initialize(
        new OpenSAMLSecurityDefaultsConfig(new SwedishEidSecurityConfiguration()),
        new OpenSAMLSecurityExtensionConfig());
  }

  @Test
  void signing2IsNotPublishedInSpMetadataAndIsNotUsedForSigning() throws Exception {
    final PkiCredential signing = TestCredentials.fromTestKeyStore("rsa-2048");
    final PkiCredential encryption = TestCredentials.fromTestKeyStore("rsa-3072");
    final PkiCredential signing2 = TestCredentials.fromTestKeyStore("rsa-4096");

    final ClientCredentials without =
        new ClientCredentials(signing, null, null, encryption, null, signing, signing, signing);
    final ClientCredentials with =
        new ClientCredentials(signing, signing2, null, encryption, null, signing, signing, signing);

    Assertions.assertSame(signing, with.getCredentialForSigning());
    Assertions.assertEquals(keyNames(createSp(without)), keyNames(createSp(with)));
    Assertions.assertEquals(
        List.of("SP Signing Certificate", "SP Encryption Certificate"), keyNames(createSp(with)));
    // The certificate of signing2 is not in the metadata
    final String metadata = createSp(with).getSpMetadata();
    Assertions.assertTrue(metadata.contains(base64(signing)));
    Assertions.assertFalse(metadata.contains(base64(signing2)));
  }

  private static List<String> keyNames(final SamlSp sp) {
    return keyDescriptors(sp).stream()
        .map(kd -> kd.getKeyInfo().getKeyNames().get(0).getValue())
        .toList();
  }

  private static String base64(final PkiCredential credential) throws Exception {
    return java.util.Base64.getEncoder().encodeToString(credential.getCertificate().getEncoded());
  }

  private static List<KeyDescriptor> keyDescriptors(final SamlSp sp) {
    return sp.getEntityDescriptor().getSPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors();
  }

  private static SamlSp createSp(final ClientCredentials credentials) {
    final EntityDescriptor template = EntityDescriptorBuilder.builder().entityID(ENTITY_ID).build();
    final SPSSODescriptor ssoDescriptor = SPSSODescriptorBuilder.builder().build();
    ssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
    template.getRoleDescriptors().add(ssoDescriptor);

    final SamlSpProperties.SpMetadataProperties metadata = new SamlSpProperties.SpMetadataProperties();
    return new SamlSp(ENTITY_ID, "Test SP", "testsp", credentials, template, metadata,
        Mockito.mock(MetadataResolver.class));
  }

}
