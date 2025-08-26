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
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGenerator;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An {@link AuthnRequestGenerator} for the test client.
 *
 * @author Martin Lindström
 */
public class CustomAuthnRequestGenerator extends SwedishEidAuthnRequestGenerator {

  public CustomAuthnRequestGenerator(@Nonnull final EntityDescriptor spMetadata,
      @Nonnull final PkiCredential signCredential, @Nonnull final MetadataResolver metadataResolver) {
    super(spMetadata, new OpenSamlCredential(signCredential), metadataResolver);
  }

  public RequestHttpObject<AuthnRequest> generateAuthnRequest(@Nonnull final SamlAuthnRequestParameterModel input)
      throws RequestGenerationException {
    return this.generateAuthnRequest(input.getIdp(), input.getRelayState(),
        new CustomAuthnRequestGeneratorContext(input));
  }

  public SamlAuthnRequestParameterModel generateAuthnRequestModel(final String idp) throws RequestGenerationException {
    final CustomAuthnRequestGeneratorContext context = new CustomAuthnRequestGeneratorContext();

    final RequestHttpObject<AuthnRequest> template = this.generateAuthnRequest(idp, null, context);

    final SamlAuthnRequestParameterModel model = new SamlAuthnRequestParameterModel();
    model.setSp(this.getSpEntityID());
    model.setIdp(idp);
    model.setPossibleRequestBindings(
        List.of(SAMLConstants.SAML2_REDIRECT_BINDING_URI, SAMLConstants.SAML2_POST_BINDING_URI));
    if ("GET".equals(template.getMethod())) {
      model.setRequestBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    }
    else {
      model.setRequestBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    }
    final AuthnRequest authnRequest = template.getRequest();

    Optional.ofNullable(authnRequest.isForceAuthnXSBoolean())
        .ifPresent(b -> model.setForceAuthn(b.getValue()));
    Optional.ofNullable(authnRequest.isPassiveXSBoolean())
        .ifPresent(b -> model.setIsPassive(b.getValue()));
    Optional.ofNullable(authnRequest.getDestination()).ifPresent(model::setDestination);

    model.setIssuer(authnRequest.getIssuer().getValue());

    final NameIDPolicy nameIdPolicy = authnRequest.getNameIDPolicy();
    if (nameIdPolicy != null) {
      final SamlAuthnRequestParameterModel.NameIdPolicy nip = new SamlAuthnRequestParameterModel.NameIdPolicy();
      nip.setFormat(nameIdPolicy.getFormat());
      Optional.ofNullable(nameIdPolicy.getAllowCreateXSBoolean()).ifPresent(a -> nip.setAllowCreate(a.getValue()));
      nip.setSpNameQualifier(nameIdPolicy.getSPNameQualifier());
      model.setNameIdPolicy(nip);
    }

    final RequestedAuthnContext requestedAuthnContext = authnRequest.getRequestedAuthnContext();
    if (requestedAuthnContext != null) {
      final List<String> rac = requestedAuthnContext.getAuthnContextClassRefs()
          .stream()
          .map(XSURI::getURI)
          .toList();
      if (!rac.isEmpty()) {
        model.setRequestedAuthnContext(new SamlAuthnRequestParameterModel.RequestedAuthnContext(rac,
            Optional.ofNullable(requestedAuthnContext.getComparison()).map(
                AuthnContextComparisonTypeEnumeration::toString).orElse(null)));
      }
    }

    final SPSSODescriptor ssoDescriptor = this.getSpMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    model.setPossibleAssertionConsumerServiceUrls(ssoDescriptor.getAssertionConsumerServices().stream()
        .map(Endpoint::getLocation)
        .toList());
    model.setAssertionConsumerServiceUrl(authnRequest.getAssertionConsumerServiceURL());

    final UserMessage userMessage = Optional.ofNullable(authnRequest.getExtensions())
        .map(e -> e.getUnknownXMLObjects(UserMessage.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(List::getFirst)
        .map(UserMessage.class::cast)
        .orElse(null);
    if (userMessage != null) {
      final SamlAuthnRequestParameterModel.UserMessageExtension umExt =
          new SamlAuthnRequestParameterModel.UserMessageExtension();
      umExt.setMimeType(userMessage.getMimeType());
      umExt.setMessages(
          userMessage.getMessages().stream()
              .map(m -> {
                final String language = "sv".equals(m.getXMLLang()) ? "Swedish"
                    : "en".equals(m.getXMLLang()) ? "English" : "Unknown language";
                return new SamlAuthnRequestParameterModel.UserMessageExtension.Message(
                    m.getXMLLang(), language, m.getContent());
              })
              .toList());
      model.setUserMessageExtension(umExt);
    }

    return model;
  }

  @Override
  protected RequestHttpObject<AuthnRequest> buildRequestHttpObject(final AuthnRequest request, final String relayState,
      final AuthnRequestGeneratorContext context, final String binding, final String destination,
      final EntityDescriptor recipientMetadata) throws RequestGenerationException {

    final CustomAuthnRequestGeneratorContext customContext = (CustomAuthnRequestGeneratorContext) context;

    if (customContext.isGenerateTemplate()) {
      return new RequestHttpObject<AuthnRequest>() {

        @Override
        public String getSendUrl() {
          return "";
        }

        @Override
        public String getDestinationUrl() {
          return destination;
        }

        @Override
        public String getMethod() {
          return SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding) ? "GET" : "POST";
        }

        @Override
        public Map<String, String> getRequestParameters() {
          return Map.of();
        }

        @Override
        public Map<String, String> getHttpHeaders() {
          return Map.of();
        }

        @Override
        public AuthnRequest getRequest() {
          return request;
        }
      };
    }
    else {
      return super.buildRequestHttpObject(request, relayState, context, binding, destination, recipientMetadata);
    }
  }
}
