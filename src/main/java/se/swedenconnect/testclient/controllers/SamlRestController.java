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
package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.shibboleth.shared.resolver.ResolverException;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.testclient.saml.SamlAuthnRequestParameterModel;
import se.swedenconnect.testclient.saml.SamlFederation;
import se.swedenconnect.testclient.saml.SamlResponseProcessingModel;
import se.swedenconnect.testclient.saml.SamlSp;
import se.swedenconnect.testclient.utils.UrlBuilderBean;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * REST controller for SAML.
 *
 * @author Martin Lindström
 */
@RestController
@RequestMapping("/saml")
public class SamlRestController {

  /** URL builder. */
  private final UrlBuilderBean urlBuilderBean;

  /** SAML SP:s. */
  private final List<SamlSp> samlSps;

  /** The federation bean. */
  private final SamlFederation samlFederation;

  /**
   * Constructor.
   *
   * @param urlBuilderBean the URL builder
   * @param samlSps the SAML SP:s
   * @param samlFederation the federation
   */
  public SamlRestController(@Nonnull final UrlBuilderBean urlBuilderBean,
      @Qualifier("testclient.saml.SpList") @Nonnull final List<SamlSp> samlSps,
      @Nonnull final SamlFederation samlFederation) {
    this.urlBuilderBean = urlBuilderBean;
    this.samlSps = samlSps;
    this.samlFederation = samlFederation;
  }

  @GetMapping(value = "/authn/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public SamlInitAuthnModel getSamlInitAuthnInfo() throws ResolverException {
    final SamlInitAuthnModel initInfo = new SamlInitAuthnModel();
    initInfo.setSps(this.getSamlSpInfo());
    final List<EntityDescriptor> idps = this.samlFederation.getIdps();
    final List<SamlIdpInfoModel> idpModelList = new ArrayList<>();
    for (final EntityDescriptor idp : idps) {
      final SamlIdpInfoModel model = new SamlIdpInfoModel();
      model.setEntityID(idp.getEntityID());
      final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(
          EntityDescriptorUtils.getSSODescriptor(idp).getExtensions(), UIInfo.class);
      if (uiInfo != null) {
        for (final DisplayName displayName : uiInfo.getDisplayNames()) {
          if (displayName.getXMLLang() != null && displayName.getXMLLang().startsWith("en")) {
            model.setDisplayName(displayName.getValue());
            break;
          }
          else if (model.getDisplayName() != null) {
            model.setDisplayName(displayName.getValue());
          }
        }
        for (final Description description : uiInfo.getDescriptions()) {
          if (description.getXMLLang() != null && description.getXMLLang().startsWith("en")) {
            model.setDescription(description.getValue());
            break;
          }
          else if (model.getDescription() != null) {
            model.setDescription(description.getValue());
          }
        }
      }
      idpModelList.add(model);
    }
    initInfo.setIdps(idpModelList);

    return initInfo;
  }

  @GetMapping(value = "/authn/template", produces = MediaType.APPLICATION_JSON_VALUE)
  public SamlAuthnRequestParameterModel getSamlAuthnRequestTemplate(
      @Nonnull @RequestParam("sp") final String sp, @Nonnull @RequestParam("idp") final String idp) {

    for (final SamlSp samlSp : this.samlSps) {
      if (samlSp.getEntityId().equals(sp)) {
        return samlSp.getTemplateRequest(idp);
      }
    }

    throw new NotFoundException("%s not found".formatted(sp));
  }

  @PostMapping(value = "/authn/generate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public SamlAuthnRequestModel generateAuthnRequest(@Nonnull @RequestBody final SamlAuthnRequestParameterModel model)
      throws RequestGenerationException {

    for (final SamlSp samlSp : this.samlSps) {
      if (samlSp.getEntityId().equals(model.getSp())) {
        final RequestHttpObject<AuthnRequest> request = samlSp.generateAuthnRequest(model);
        final SamlAuthnRequestModel authnRequestModel = new SamlAuthnRequestModel();
        authnRequestModel.setSp(model.getSp());
        authnRequestModel.setIdp(model.getIdp());
        authnRequestModel.setId(request.getRequest().getID());
        authnRequestModel.setIssueInstant(request.getRequest().getIssueInstant());
        authnRequestModel.setUrl(request.getSendUrl());
        authnRequestModel.setMethod(request.getMethod());
        authnRequestModel.setRelayState(request.getRequestParameters().get("RelayState"));
        if ("POST".equalsIgnoreCase(request.getMethod())) {
          authnRequestModel.setParameters(request.getRequestParameters());
        }
        try {
          Element element = request.getRequest().getDOM();
          if (element == null) {
            element = XMLObjectSupport.marshall(request.getRequest());
          }
          authnRequestModel.setAuthnRequest(SerializeSupport.prettyPrintXML(element));
        }
        catch (final Exception e) {
          throw new RuntimeException("Failed to get serialize request", e);
        }
        return authnRequestModel;
      }
    }

    throw new NotFoundException("%s not found".formatted(model.getSp()));
  }

  @PostMapping(value = "/authn/verify", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
  public SamlResponseProcessingModel verifySamlResponse(
      @Nonnull @RequestBody final SamlResponseValidationInput responseInput) {

    for (final SamlSp samlSp : this.samlSps) {
      if (samlSp.getEntityId().equals(responseInput.getSp())) {
        return samlSp.processResponse(responseInput.getResponseData(), responseInput.getAuthnRequest(),
            responseInput.getSentRelayState());
      }
    }

    throw new NotFoundException("%s not found".formatted(responseInput.getSp()));
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlResponseValidationInput {

    private String sp;

    @JsonProperty("authn_request")
    private String authnRequest;

    @JsonProperty("sent_relay_state")
    private String sentRelayState;

    @JsonProperty("response_data")
    private SamlController.SamlResponseData responseData;
  }

  @GetMapping(value = "/sp/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<SamlSpInfoModel> getSamlSpInfo() {
    return this.samlSps.stream()
        .map(sp -> new SamlSpInfoModel(sp.getEntityId(), sp.getDescription(),
            this.urlBuilderBean.buildUrl(SamlSpMetadataController.SP_METADATA_BASEPATH, sp.getPathSuffix())))
        .toList();
  }

  @GetMapping(value = "/sp/metadata", produces = MediaType.TEXT_PLAIN_VALUE)
  public String getSamlSpMetadata(
      @Nonnull
      @RequestParam("sp") final String sp) {
    return this.samlSps.stream()
        .filter(s -> s.getEntityId().equals(sp))
        .findFirst()
        .map(SamlSp::getSpMetadata)
        .orElseThrow(() -> new NotFoundException("%s not found".formatted(sp)));
  }

  @GetMapping(value = "/idp/metadata", produces = MediaType.TEXT_PLAIN_VALUE)
  public String getSamlIdpMetadata(
      @Nonnull
      @RequestParam("idp") final String idp) {

    try {
      final EntityDescriptor metadata = this.samlFederation.getIdp(idp);
      if (metadata == null) {
        throw new NotFoundException("%s not found".formatted(idp));
      }
      Element element = metadata.getDOM();
      if (element == null) {
        element = XMLObjectSupport.marshall(metadata);
      }
      return SerializeSupport.prettyPrintXML(element);
    }
    catch (final ResolverException | MarshallingException e) {
      throw new RuntimeException("Failed to get metadata IdP metadata", e);
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlSpInfoModel {

    @JsonProperty("entity_id")
    private String entityID;

    private String description;

    @JsonProperty("metadata_url")
    private String metadataUrl;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlInitAuthnModel {
    private List<SamlSpInfoModel> sps;
    private List<SamlIdpInfoModel> idps;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlIdpInfoModel {

    @JsonProperty("entity_id")
    private String entityID;

    @JsonProperty("display_name")
    private String displayName;

    private String description;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlAuthnRequestModel {

    private String sp;

    private String idp;

    private String id;

    @JsonProperty("issue_instant")
    private Instant issueInstant;

    // GET or POST
    private String method;

    private String url;

    private Map<String, String> parameters;

    @JsonProperty("authn_request")
    private String authnRequest;

    @JsonProperty("relay_state")
    private String relayState;

  }

}
