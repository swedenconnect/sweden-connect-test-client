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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * @author Martin Lindström
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.ALWAYS)
public class SamlAuthnRequestModel {

  @JsonProperty("possible_request_bindings")
  private List<String> possibleRequestBindings;

  @JsonProperty("request_binding")
  private String requestBinding;

  @JsonProperty("force_authn")
  private Boolean forceAuthn;

  @JsonProperty("is_passive")
  private Boolean isPassive;

  private String destination;

  @JsonProperty("issue_instant")
  private Instant issueInstant;

  private String issuer;

  @JsonProperty("issuer_present")
  private boolean issuerPresent = true;

  @JsonProperty("name_id_policy")
  private NameIdPolicy nameIdPolicy;

  @JsonProperty("requested_authn_context_class_uris")
  private List<String> requestedAuthnContextClassUris;

  @JsonProperty("possible_assertion_consumer_service_urls")
  private List<String> possibleAssertionConsumerServiceUrls;

  @JsonProperty("assertion_consumer_service_url")
  private String assertionConsumerServiceUrl;

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class NameIdPolicy {
    private String format;

    @JsonProperty("allow_create")
    private Boolean allowCreate;

    @JsonProperty("sp_name_qualifier")
    private String spNameQualifier;
  }

}
