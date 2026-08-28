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

import jakarta.annotation.Nonnull;
import lombok.Getter;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.RequestedAttributeBuilder;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingException;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingInput;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseStatusErrorException;
import se.swedenconnect.security.credential.opensaml.KeyDescriptorTransformerFunction;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.testclient.config.SamlSpProperties;
import se.swedenconnect.testclient.config.SamlSpProperties.SpMetadataProperties.AttributeConsumingServiceProperties;
import se.swedenconnect.testclient.controllers.SamlController;
import se.swedenconnect.testclient.credentials.ClientCredentials;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
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

  /** Suffix for SAML paths. */
  @Getter
  private final String pathSuffix;

  /** The SAML SP metadata. */
  @Getter
  private final EntityDescriptor entityDescriptor;

  /** The container for SAML SP metadata. */
  @Getter
  private final EntityDescriptorContainer entityDescriptorContainer;

  /** The SP client credentials. */
  private final ClientCredentials credentials;

  /** The metadata resolver. */
  private final MetadataResolver metadataResolver;

  private final CustomAuthnRequestGenerator authnRequestGenerator;

  private final CustomAuthnRequestGenerator authnRequestGeneratorNoSigning;

  private final CustomResponseProcessor responseProcessor;

  public SamlSp(@Nonnull final String entityId, @Nonnull final String description,
      @Nonnull final String pathSuffix, @Nonnull final ClientCredentials credentials,
      @Nonnull final EntityDescriptor entityDescriptorTemplate,
      @Nonnull final SamlSpProperties.SpMetadataProperties metadataProperties,
      @Nonnull final MetadataResolver metadataResolver) {
    this.entityId = entityId;
    this.description = description;
    this.pathSuffix = pathSuffix;
    this.credentials = credentials;
    this.metadataResolver = metadataResolver;

    this.entityDescriptor = this.buildMetadata(entityDescriptorTemplate, metadataProperties);

    this.entityDescriptorContainer = new EntityDescriptorContainer(this.entityDescriptor,
        new OpenSamlCredential(this.credentials.getCredentialForSigning()));
    this.entityDescriptorContainer.setValidity(Duration.ofDays(7));

    this.authnRequestGenerator = new CustomAuthnRequestGenerator(this.entityDescriptor,
        this.credentials.getCredentialForSigning(), this.metadataResolver);
    this.authnRequestGeneratorNoSigning = new CustomAuthnRequestGenerator(this.entityDescriptor, this.metadataResolver);

    this.responseProcessor =
        new CustomResponseProcessor(this.metadataResolver, this.credentials.getCredentialsForEncryption());
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
      if (extensions == null) {
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
        || this.credentials.getFutureSigning() != null) {
      if (this.credentials.getFutureSigning() != null) {
        ssoDescriptor.getKeyDescriptors().add(
            this.credentials.getFutureSigning().transform(
                KeyDescriptorTransformerFunction.function()
                    .withUsageTypeFunction(c -> UsageType.SIGNING)
                    .withKeyNameFunction(c -> "SP Future Signing Certificate")));
      }
      ssoDescriptor.getKeyDescriptors().add(
          this.credentials.getCredentialForSigning().transform(
              KeyDescriptorTransformerFunction.function()
                  .withUsageTypeFunction(c -> UsageType.SIGNING)
                  .withKeyNameFunction(c -> "SP Signing Certificate")));
      ssoDescriptor.getKeyDescriptors().add(
          Optional.ofNullable(this.credentials.getEncryption())
              .orElseGet(this.credentials::getDefaultCredential)
              .transform(KeyDescriptorTransformerFunction.function()
                  .withUsageTypeFunction(c -> UsageType.ENCRYPTION)
                  .withKeyNameFunction(c -> "SP Encryption Certificate")));
    }
    else {
      ssoDescriptor.getKeyDescriptors().add(
          this.credentials.getDefaultCredential().transform(
              KeyDescriptorTransformerFunction.function()
                  .withUsageTypeFunction(c -> UsageType.UNSPECIFIED)
                  .withKeyNameFunction(c -> "SP Signing and Encryption")));
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

  @Nonnull
  public RequestHttpObject<AuthnRequest> generateAuthnRequest(@Nonnull final SamlAuthnRequestParameterModel model)
      throws RequestGenerationException {

    final CustomAuthnRequestGenerator generator =
        model.getSignatureOption() == SamlAuthnRequestParameterModel.SignatureOption.NO_SIGNATURE
            ? this.authnRequestGeneratorNoSigning
            : this.authnRequestGenerator;

    return generator.generateAuthnRequest(model, this.credentials.getNonRegisteredCredential());
  }

  @Nonnull
  public SamlAuthnRequestParameterModel getTemplateRequest(@Nonnull final String idp) {
    try {
      return this.authnRequestGenerator.generateAuthnRequestModel(idp);
    }
    catch (final RequestGenerationException e) {
      throw new RuntimeException(e.getMessage());
    }
  }

  @Nonnull
  public String getSpMetadata() {
    try {
      Element element = this.entityDescriptor.getDOM();
      if (element == null) {
        element = XMLObjectSupport.marshall(this.entityDescriptor);
      }
      return SerializeSupport.prettyPrintXML(element);
    }
    catch (final Exception e) {
      throw new RuntimeException("Failed to serialize metadata", e);
    }
  }

  public SamlResponseProcessingModel processResponse(@Nonnull final SamlController.SamlResponseData responseData,
      @Nonnull final String authnRequestString, @Nonnull final String sentRelayState) {

    final AuthnRequest authnRequest;
    try {
      authnRequest = (AuthnRequest) XMLObjectSupport.unmarshallFromInputStream(
          XMLObjectProviderRegistrySupport.getParserPool(),
          new ByteArrayInputStream(authnRequestString.getBytes(StandardCharsets.UTF_8)));
    }
    catch (final Exception e) {
      return new SamlResponseProcessingModel(e, responseData.getRelayState());
    }

    final ResponseProcessingInput input = new ResponseProcessingInput() {

      @Override
      public AuthnRequest getAuthnRequest(final String id) {
        return authnRequest;
      }

      @Override
      public String getRequestRelayState(final String id) {
        return sentRelayState;
      }

      @Override
      public String getReceiveURL() {
        return responseData.getReceiveUrl();
      }

      @Override
      public Instant getReceiveInstant() {
        return responseData.getReceiveInstant();
      }

      @Override
      public String getClientIpAddress() {
        return null;
      }

      @Override
      public X509Certificate getClientCertificate() {
        return null;
      }
    };

    try {
      final ResponseProcessingResult result = this.responseProcessor.processSamlResponse(
          responseData.getSamlResponse(), responseData.getRelayState(), input, null);

      return new SamlResponseProcessingModel(result, responseData.getRelayState());
    }
    catch (final ResponseStatusErrorException | ResponseProcessingException e) {
      return new SamlResponseProcessingModel(e, responseData.getRelayState());
    }
  }

}
