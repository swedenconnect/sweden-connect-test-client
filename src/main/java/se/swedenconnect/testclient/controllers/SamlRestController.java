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
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.testclient.saml.SamlFederation;
import se.swedenconnect.testclient.saml.SamlSp;
import se.swedenconnect.testclient.utils.UrlBuilderBean;

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
  public SamlRestController(@Nonnull final UrlBuilderBean urlBuilderBean, @Nonnull final List<SamlSp> samlSps,
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
      try {
        Element element = idp.getDOM();
        if (element == null) {
          element = XMLObjectSupport.marshall(idp);
        }
        model.setMetadata(SerializeSupport.prettyPrintXML(element));
      }
      catch (final Exception e) {
        throw new RuntimeException("Failed to get metadata IdP metadata", e);
      }
      idpModelList.add(model);
    }
    initInfo.setIdps(idpModelList);

    return initInfo;
  }

  @GetMapping(value = "/sp/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<SamlSpInfoModel> getSamlSpInfo() {
    return this.samlSps.stream()
        .map(sp -> new SamlSpInfoModel(sp.getEntityId(), sp.getDescription(),
            this.urlBuilderBean.buildUrl(SamlSpMetadataController.SP_METADATA_BASEPATH, sp.getPathPrefix())))
        .toList();
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

    private String metadata;

  }

}
