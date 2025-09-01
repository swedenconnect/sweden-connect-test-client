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
package se.swedenconnect.testclient.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.Logo;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.testclient.controllers.SamlController;
import se.swedenconnect.testclient.saml.SamlFederation;
import se.swedenconnect.testclient.saml.SamlSp;
import se.swedenconnect.testclient.utils.ClientCredentials;
import se.swedenconnect.testclient.utils.UrlBuilderBean;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the Sweden Connect Test Client configuration.
 *
 * @author Martin Lindström
 */
@Configuration
@DependsOn("openSAML")
@EnableConfigurationProperties(TestClientConfigurationProperties.class)
public class TestClientConfiguration {

  private final TestClientConfigurationProperties properties;

  private final PkiCredentialFactory credentialFactory;

  private final SslBundles sslBundles;

  private final UrlBuilderBean urlBuilder;

  public TestClientConfiguration(@Nonnull final TestClientConfigurationProperties properties,
      @Nonnull final PkiCredentialFactory credentialFactory, @Nonnull final SslBundles sslBundles,
      @Nonnull final UrlBuilderBean urlBuilder) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
    this.sslBundles = sslBundles;
    this.urlBuilder = urlBuilder;
  }

  @Bean
  @Nonnull
  SamlFederation samlFederation() throws Exception {
    return new SamlFederation(this.properties.getSaml().getFederation(), this.sslBundles);
  }

  @Bean("testclient.DefaultCredential")
  @Nullable
  PkiCredential defaultCredential() throws Exception {
    return this.properties.getDefaultCredential() != null
        ? this.credentialFactory.createCredential(this.properties.getDefaultCredential())
        : null;
  }

  @Bean("testclient.NonRegisteredCredential")
  @Nonnull
  PkiCredential nonRegisteredCredential() throws Exception {
    return this.credentialFactory.createCredential(this.properties.getNonRegisteredCredential());
  }

  @Bean
  List<SamlSp> getSamlSps() throws Exception {
    final List<SamlSp> sps = new ArrayList<>();
    for (final SamlSpProperties spp : this.properties.getSaml().getSps()) {

      final EntityDescriptor entityDescriptorTemplate =
          XMLObjectSupport.cloneXMLObject(this.templateEntityDescriptor());

      final AssertionConsumerService acs = AssertionConsumerServiceBuilder.builder()
          .binding(SAMLConstants.SAML2_POST_BINDING_URI)
          .location(this.urlBuilder.buildUrl(SamlController.ASSERTION_CONSUMER_SERVICE_BASE_PATH, spp.getPathPrefix()))
          .index(0)
          .isDefault(true)
          .build();
      SPSSODescriptor ssoDescriptor = entityDescriptorTemplate.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
      if (ssoDescriptor == null) {
        ssoDescriptor = SPSSODescriptorBuilder.builder().build();
        entityDescriptorTemplate.getRoleDescriptors().add(ssoDescriptor);
      }
      ssoDescriptor.getAssertionConsumerServices().clear();
      ssoDescriptor.getAssertionConsumerServices().add(acs);

      sps.add(new SamlSp(spp.getEntityId(), spp.getDescription(), spp.getPathPrefix(),
          this.createClientCredentials(spp.getCredentials()), entityDescriptorTemplate,
          spp.getMetadata(), this.samlFederation().getMetadataProvider().getMetadataResolver()));
    }
    return sps;
  }

  @Bean("testclient.TemplateEntityDescriptor")
  EntityDescriptor templateEntityDescriptor() throws Exception {
    final SamlProperties.CommonSpMetadataProperties mp = this.properties.getSaml().getCommonMetadata();
    final EntityDescriptorBuilder builder = mp.getMetadataTemplate() != null
        ? new EntityDescriptorBuilder(mp.getMetadataTemplate().getInputStream())
        : new EntityDescriptorBuilder();

    if (!mp.getDefaultEntityCategories().isEmpty()) {
      builder.extensions(builder.getExtensionsBuilder()
          .extension(EntityAttributesBuilder.builder()
              .entityCategoriesAttribute(mp.getDefaultEntityCategories())
              .build())
          .build());
    }

    final SPSSODescriptor ssoDescriptor = builder.object().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    if (ssoDescriptor != null) {
      final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(ssoDescriptor.getExtensions(), UIInfo.class);
      if (uiInfo != null) {
        for (final Logo logo : uiInfo.getLogos()) {
          if (logo.getURI() != null && logo.getURI().startsWith("/")) {
            logo.setURI(this.urlBuilder.buildUrl(logo.getURI()));
          }
        }
      }
      else {
        if (ssoDescriptor.getExtensions() == null) {
          ssoDescriptor.setExtensions(ExtensionsBuilder.builder().build());
        }
        ssoDescriptor.getExtensions().getUnknownXMLObjects().add(UIInfoBuilder.builder()
            .logos(List.of(
                LogoBuilder.logo(this.urlBuilder.buildUrl("/images/logo.svg"), 56, 280),
                LogoBuilder.logo(this.urlBuilder.buildUrl("/images/logo-notext.svg"), 256, 256)))
            .build());
      }
    }

    return builder.build();
  }

  private ClientCredentials createClientCredentials(@Nullable final SamlSpProperties.CredentialsProperties cp)
      throws Exception {
    if (cp == null) {
      return new ClientCredentials(null, null, null, null, null, this.defaultCredential(),
          this.nonRegisteredCredential());
    }
    return new ClientCredentials(
        cp.getSigning() != null ? this.credentialFactory.createCredential(cp.getSigning()) : null,
        cp.getFutureSigningCertificate(),
        cp.getEncryption() != null ? this.credentialFactory.createCredential(cp.getEncryption()) : null,
        cp.getPreviousEncryption() != null ? this.credentialFactory.createCredential(cp.getPreviousEncryption()) : null,
        cp.getMetadata() != null ? this.credentialFactory.createCredential(cp.getMetadata()) : null,
        this.defaultCredential(),
        this.nonRegisteredCredential());
  }

}
