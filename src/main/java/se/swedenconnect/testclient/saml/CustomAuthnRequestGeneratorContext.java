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

import jakarta.annotation.Nullable;
import lombok.Getter;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.x509.X509Credential;
import se.swedenconnect.opensaml.saml2.core.build.NameIDPolicyBuilder;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.MatchValue;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.MessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.UserMessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.signservice.build.SignMessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Custom {@link AuthnRequestGeneratorContext}.
 *
 * @author Martin Lindström
 */
public class CustomAuthnRequestGeneratorContext implements SwedishEidAuthnRequestGeneratorContext {

  @Getter
  private final boolean generateTemplate;

  @Getter
  private final SamlAuthnRequestParameterModel model;

  private Map<String, String> displayNames;
  private boolean isSignService;
  private PkiCredential nonRegisteredCredential;

  public CustomAuthnRequestGeneratorContext(final EntityDescriptor entityDescriptor) {
    this.generateTemplate = true;
    this.model = null;

    final SPSSODescriptor sso = (SPSSODescriptor) EntityDescriptorUtils.getSSODescriptor(entityDescriptor);
    final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(sso.getExtensions(), UIInfo.class);
    if (uiInfo != null) {
      this.displayNames =
          uiInfo.getDisplayNames().stream().collect(Collectors.toMap(
              d -> Optional.ofNullable(d.getXMLLang()).orElse("nolang"), XSString::getValue));
    }
    this.isSignService = EntityDescriptorUtils.getEntityCategories(entityDescriptor)
        .contains(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri());
  }

  public CustomAuthnRequestGeneratorContext(final SamlAuthnRequestParameterModel model,
      final PkiCredential nonRegisteredCredential) {
    this.model = model;
    this.generateTemplate = false;
    this.nonRegisteredCredential = nonRegisteredCredential;
  }

  private String getDisplayName(final String lang) {
    if (this.displayNames == null || this.displayNames.isEmpty()) {
      return null;
    }
    return Optional.ofNullable(this.displayNames.get(lang))
        .orElseGet(() -> Optional.ofNullable(this.displayNames.get("nolang"))
            .orElseGet(() -> this.displayNames.values().stream().findFirst().orElse("")));
  }

  @Override
  public String getPreferredBinding() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getPreferredBinding();
    }
    return Optional.ofNullable(this.model.getRequestBinding())
        .orElse(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
  }

  @Override
  public Boolean getForceAuthnAttribute() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getForceAuthnAttribute();
    }
    return this.model.getForceAuthn();
  }

  @Override
  public Boolean getIsPassiveAttribute() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getIsPassiveAttribute();
    }
    return this.model.getIsPassive();
  }

  @Override
  public NameIDPolicyBuilderFunction getNameIDPolicyBuilderFunction() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getNameIDPolicyBuilderFunction();
    }
    return _x -> {
      if (this.model.getNameIdPolicy() == null) {
        return null;
      }
      return NameIDPolicyBuilder.builder()
          .format(this.model.getNameIdPolicy().getFormat())
          .allowCreate(this.model.getNameIdPolicy().getAllowCreate())
          .spNameQualifier(this.model.getNameIdPolicy().getSpNameQualifier())
          .build();
    };
  }

  @Override
  public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getRequestedAuthnContextBuilderFunction();
    }
    return (list, hok) -> {
      if (this.model.getRequestedAuthnContext() == null) {
        return null;
      }
      return RequestedAuthnContextBuilder.builder()
          .comparison(toComparisonEnum(this.model.getRequestedAuthnContext().getComparison()))
          .authnContextClassRefs(Optional.ofNullable(this.model.getRequestedAuthnContext().getUris())
              .orElseGet(Collections::emptyList))
          .build();
    };
  }

  @Nullable
  private static AuthnContextComparisonTypeEnumeration toComparisonEnum(@Nullable final String c) {
    if (c == null) {
      return null;
    }
    for (final AuthnContextComparisonTypeEnumeration e : AuthnContextComparisonTypeEnumeration.values()) {
      if (e.toString().equals(c)) {
        return e;
      }
    }
    return null;
  }

  @Override
  public PrincipalSelectionBuilderFunction getPrincipalSelectionBuilderFunction() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getPrincipalSelectionBuilderFunction();
    }
    else {
      if (this.model.getRequestedPrincipalSelection() != null) {
        return () -> {
          final List<MatchValue> values = new ArrayList<>();
          this.model.getRequestedPrincipalSelection().forEach(
              rps -> values.add(MatchValueBuilder.builder()
                  .name(rps.getName())
                  .value(rps.getValue())
                  .nameFormat(Attribute.URI_REFERENCE)
                  .build()));
          return PrincipalSelectionBuilder.builder()
              .matchValues(values)
              .build();
        };
      }
      else {
        return () -> null;
      }
    }
  }

  @Override
  public UserMessageBuilderFunction getUserMessageBuilderFunction() {
    if (this.generateTemplate) {

      if (this.isSignService) {
        return (um) -> null;
      }

      final String swedish = "Du loggar nu in till %s"
          .formatted(Optional.ofNullable(this.getDisplayName("sv")).orElse("testtjänsten"));
      final String english = "You are now logging in to %s"
          .formatted(Optional.ofNullable(this.getDisplayName("en")).orElse("the Test Service"));

      return e -> UserMessageBuilder.builder()
          .mimeType(UserMessage.DEFAULT_MIME_TYPE)
          .message(MessageBuilder.builder()
              .language("sv")
              .content(swedish)
              .build())
          .message(MessageBuilder.builder()
              .language("en")
              .content(english)
              .build())
          .build();
    }
    else {
      if (this.model.getUserMessageExtension() == null) {
        return (um) -> null;
      }
      else {
        return e -> {
          final UserMessageBuilder builder = UserMessageBuilder.builder();
          Optional.ofNullable(this.model.getUserMessageExtension().getMimeType()).ifPresent(builder::mimeType);
          if (this.model.getUserMessageExtension().getMessages() != null) {
            for (final SamlAuthnRequestParameterModel.UserMessageExtension.Message m :
                this.model.getUserMessageExtension().getMessages()) {
              final MessageBuilder mbuilder = MessageBuilder.builder();
              Optional.ofNullable(m.getLangCode()).ifPresent(mbuilder::language);
              Optional.ofNullable(m.getMessage()).ifPresent(mbuilder::content);
              builder.message(mbuilder.build());
            }
          }
          return builder.build();
        };
      }
    }
  }

  @Override
  public SignMessageBuilderFunction getSignMessageBuilderFunction() {
    if (this.generateTemplate) {
      final String message = "Signature requested by %s"
          .formatted(Optional.ofNullable(this.getDisplayName("en")).orElse("the Test Service"));

      return (md, e) -> {
        return SignMessageBuilder.builder()
            .message(message)
            .mimeType(SignMessageMimeTypeEnum.TEXT)
            .displayEntity(md.getEntityID())
            .mustShow(true)
            .build();
      };
    }
    else if (this.model.getSignMessage() != null) {
      return SwedishEidAuthnRequestGeneratorContext.super.getSignMessageBuilderFunction();
    }
    else {
      return (md, e) -> null;
    }
  }

  @Override
  public AuthnRequestCustomizer getAuthnRequestCustomizer() {
    if (this.generateTemplate) {
      return SwedishEidAuthnRequestGeneratorContext.super.getAuthnRequestCustomizer();
    }
    else {
      return authnRequest -> {
        authnRequest.setDestination(Optional.ofNullable(this.model.getDestination())
            .map(String::trim)
            .filter(d -> !d.isEmpty())
            .orElse(null));
        Optional.ofNullable(this.model.getIssueInstant())
            .ifPresent(authnRequest::setIssueInstant);
        Optional.ofNullable(this.model.getIssuer())
            .ifPresentOrElse(issuer -> authnRequest.getIssuer().setValue(issuer),
                () -> authnRequest.setIssuer(null));
        Optional.ofNullable(this.model.getAssertionConsumerServiceUrl())
            .ifPresentOrElse(authnRequest::setAssertionConsumerServiceURL,
                () -> authnRequest.setAssertionConsumerServiceURL(null));

      };
    }
  }

  @Override
  public X509Credential getOverrideSignCredential() {
    if (!this.generateTemplate
        && SamlAuthnRequestParameterModel.SignatureOption.OTHER_SIGNATURE == this.model.getSignatureOption()) {
      return new OpenSamlCredential(this.nonRegisteredCredential);
    }
    else {
      return SwedishEidAuthnRequestGeneratorContext.super.getOverrideSignCredential();
    }
  }
}
