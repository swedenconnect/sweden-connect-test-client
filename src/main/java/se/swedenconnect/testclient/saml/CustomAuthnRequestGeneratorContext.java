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
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import se.swedenconnect.opensaml.saml2.core.build.NameIDPolicyBuilder;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.MatchValue;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.MessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.build.UserMessageBuilder;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Custom {@link AuthnRequestGeneratorContext}.
 *
 * @author Martin Lindström
 */
public class CustomAuthnRequestGeneratorContext implements SwedishEidAuthnRequestGeneratorContext {

  @Getter
  private final boolean generateTemplate;

  private final SamlAuthnRequestParameterModel model;

  public CustomAuthnRequestGeneratorContext() {
    this.generateTemplate = true;
    this.model = null;
  }

  public CustomAuthnRequestGeneratorContext(final SamlAuthnRequestParameterModel model) {
    this.model = model;
    this.generateTemplate = false;
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
        return null;
      }
    }
  }

  @Override
  public UserMessageBuilderFunction getUserMessageBuilderFunction() {
    if (this.generateTemplate) {
      return e -> UserMessageBuilder.builder()
          .mimeType(UserMessage.DEFAULT_MIME_TYPE)
          .message(MessageBuilder.builder()
              .language("sv")
              .content("Detta är ett exempelmeddelande")
              .build())
          .message(MessageBuilder.builder()
              .language("en")
              .content("This is an example message")
              .build())
          .build();
    }
    else {
      if (this.model.getUserMessageExtension() == null) {
        return null;
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
}
