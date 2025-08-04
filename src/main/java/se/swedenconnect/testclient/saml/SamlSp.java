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
package se.swedenconnect.testclient.saml;

import jakarta.annotation.Nonnull;
import lombok.Getter;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.testclient.config.SamlSpProperties;
import se.swedenconnect.testclient.config.SamlSpProperties.SpMetadataProperties.AttributeConsumingServiceProperties;
import se.swedenconnect.testclient.utils.ClientCredentials;

import java.time.Duration;
import java.util.Optional;

/**
 * Representation of a SAML SP.
 *
 * @author Martin Lindström
 */
public class SamlSp {

  /** The entityID. */
  @Getter
  private final String entityId;

  /** SP description. */
  @Getter
  private final String description;

  /** Prefix for SAML paths. */
  @Getter
  private final String pathPrefix;

  /** The SAML SP metadata. */
  @Getter
  private final EntityDescriptor entityDescriptor;

  /** The container for SAML SP metadata. */
  @Getter
  private final EntityDescriptorContainer entityDescriptorContainer;

  /** The SP client credentials. */
  private final ClientCredentials credentials;

  public SamlSp(@Nonnull final String entityId, @Nonnull final String description,
      @Nonnull final String pathPrefix, @Nonnull final ClientCredentials credentials,
      @Nonnull final EntityDescriptor entityDescriptorTemplate,
      @Nonnull final SamlSpProperties.SpMetadataProperties metadataProperties) {
    this.entityId = entityId;
    this.description = description;
    this.pathPrefix = pathPrefix;
    this.credentials = credentials;

    this.entityDescriptor = this.buildMetadata(entityDescriptorTemplate, metadataProperties);

    this.entityDescriptorContainer = new EntityDescriptorContainer(this.entityDescriptor,
        new OpenSamlCredential(this.credentials.getCredentialForSigning()));
    this.entityDescriptorContainer.setValidity(Duration.ofDays(7));
  }

  /**
   * Constructs the SAML SP metadata document.
   *
   * @param template the entity descriptor template
   * @return an {@link EntityDescriptor}
   */
  @Nonnull
  private EntityDescriptor buildMetadata(@Nonnull final EntityDescriptor template,
      @Nonnull final SamlSpProperties.SpMetadataProperties properties) {
    final EntityDescriptorBuilder builder = new EntityDescriptorBuilder(template, false);
    builder.entityID(this.entityId);

    if (properties.getEntityCategories() != null) {
      Extensions extensions = template.getExtensions();
      if (extensions != null) {
        extensions = ExtensionsBuilder.builder().build();
        template.setExtensions(extensions);
      }
      extensions.getUnknownXMLObjects().removeIf(EntityAttributes.class::isInstance);
      extensions.getUnknownXMLObjects().add(EntityAttributesBuilder.builder()
          .entityCategoriesAttribute(properties.getEntityCategories())
          .build());
    }
    final SPSSODescriptor ssoDescriptor = template.getSPSSODescriptor(SAMLConstants.SAML20P_NS);

    if (properties.getNameIdFormats() != null) {
      ssoDescriptor.getNameIDFormats().clear();
      for (final String id : properties.getNameIdFormats()) {
        final NameIDFormat name = (NameIDFormat) XMLObjectSupport.buildXMLObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        name.setURI(id);
        ssoDescriptor.getNameIDFormats().add(name);
      }
    }
    if (properties.getWantsAssertionsSigned() != null) {
      ssoDescriptor.setWantAssertionsSigned(properties.getWantsAssertionsSigned());
    }
    if (properties.getUiInfo() != null) {
      final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(ssoDescriptor.getExtensions(), UIInfo.class);
      if (properties.getUiInfo().getDisplayName() != null) {
        uiInfo.getDisplayNames().clear();
        for (final LocalizedString s : properties.getUiInfo().getDisplayName()) {
          final DisplayName dn = (DisplayName) XMLObjectSupport.buildXMLObject(DisplayName.DEFAULT_ELEMENT_NAME);
          dn.setValue(s.getLocalString());
          dn.setXMLLang(s.getLanguage());
          uiInfo.getDisplayNames().add(dn);
        }
      }
      if (properties.getUiInfo().getDescription() != null) {
        uiInfo.getDescriptions().clear();
        for (final LocalizedString s : properties.getUiInfo().getDescription()) {
          final Description d = (Description) XMLObjectSupport.buildXMLObject(Description.DEFAULT_ELEMENT_NAME);
          d.setValue(s.getLocalString());
          d.setXMLLang(s.getLanguage());
          uiInfo.getDescriptions().add(d);
        }
      }
    }

    ssoDescriptor.getKeyDescriptors().clear();

    if (this.credentials.getSigning() != null || this.credentials.getEncryption() != null
        || this.credentials.getFutureSigningCertificate() != null) {
      if (this.credentials.getFutureSigningCertificate() != null) {
        ssoDescriptor.getKeyDescriptors().add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.SIGNING)
                .certificate(this.credentials.getFutureSigningCertificate())
                .keyName("SP Future Signing Certificate")
                .build());
      }
      ssoDescriptor.getKeyDescriptors().add(
          KeyDescriptorBuilder.builder()
              .use(UsageType.SIGNING)
              .certificate(this.credentials.getCredentialForSigning().getCertificate())
              .keyName("SP Signing Certificate")
              .build());
      ssoDescriptor.getKeyDescriptors().add(
          KeyDescriptorBuilder.builder()
              .use(UsageType.ENCRYPTION)
              .certificate(Optional.ofNullable(this.credentials.getEncryption())
                  .orElseGet(this.credentials::getDefaultCredential)
                  .getCertificate())
              .keyName("SP Encryption Certificate")
              .build());
    }
    else {
      ssoDescriptor.getKeyDescriptors().add(
          KeyDescriptorBuilder.builder()
              .certificate(this.credentials.getDefaultCredential().getCertificate())
              .keyName("SP Signing and Encryption")
              .build());
    }

    if (properties.getAttributeConsumingServices() != null) {
      ssoDescriptor.getAttributeConsumingServices().clear();
      int index = 0;
      for (final AttributeConsumingServiceProperties acs : properties.getAttributeConsumingServices()) {
        final AttributeConsumingServiceBuilder b = AttributeConsumingServiceBuilder.builder()
            .index(index++)
            .isDefault(Optional.ofNullable(acs.getIsDefault()).orElse(false))
            .serviceNames(acs.getServiceName());
        if (acs.getRequestedAttributes() != null) {
          b.requestedAttributes(acs.getRequestedAttributes().stream()
              .map(ra -> RequestedAttributeBuilder.builder(ra.getAttributeName())
                  .isRequired(Optional.ofNullable(ra.getRequired()).orElse(false))
                  .build())
              .toList());
        }
        ssoDescriptor.getAttributeConsumingServices().add(b.build());
      }
    }

    return builder.build();
  }

}
