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
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import se.swedenconnect.testclient.saml.SamlFederation;

import java.time.Instant;
import java.util.Map;

/**
 * The REST controller for the SAML federation metadata.
 *
 * @author Martin Lindström
 */
@RestController
@RequestMapping("/saml/federation")
@ConditionalOnProperty(value = "testclient.saml.enabled", havingValue = "true")
public class SamlFederationMetadataController {

  private final SamlFederation samlFederation;

  public SamlFederationMetadataController(@Nonnull final SamlFederation samlFederation) {
    this.samlFederation = samlFederation;
  }

  @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public SamlMetadataInfoModel getFederationInfo() {
    return new SamlMetadataInfoModel(
        this.samlFederation.getDescription(),
        this.samlFederation.getMetadataLocation(),
        this.samlFederation.getLastUpdate());
  }

  @GetMapping(value = "/metadata", produces = MediaType.APPLICATION_JSON_VALUE)
  public Map<String, String> getMetadata() {
    try {
      Element element = this.samlFederation.getMetadataProvider().getMetadataDOM();
      if (element == null) {
        element = XMLObjectSupport.marshall(this.samlFederation.getMetadataProvider().getMetadata());
      }
      return Map.of("metadata", SerializeSupport.prettyPrintXML(element));
    }
    catch (final ResolverException | MarshallingException e) {
      throw new RuntimeException("Failed to get metadata", e);
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class SamlMetadataInfoModel {
    private String description;
    private SamlFederation.MetadataLocation location;

    @JsonProperty("last_update")
    private Instant lastUpdate;
  }

}
