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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.List;

/**
 * REST Controller for OpenID Connect support.
 *
 * @author Martin Lindström
 */
@RestController
@RequestMapping("/oidc")
public class OidcRestController {

  /** SAML SP:s. */
  private final List<OidcRp> oidcRps;

  public OidcRestController(@Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> oidcRps) {
    this.oidcRps = oidcRps;
  }

  @GetMapping(value = "/rp/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public List<OidcRpInfoModel> getOidcRpInfo() {
    return this.oidcRps.stream()
        .map(rp -> new OidcRpInfoModel(rp.getEntityId(), rp.getDescription(),
            rp.getMetadata().toJSONObject(true).toJSONString()))
        .toList();
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class OidcRpInfoModel {
    @JsonProperty("entity-id")
    private String entityId;
    private String description;
    private String metadataJson;
  }
}
