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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Model for parameters for an AuthnRequest.
 *
 * @author Martin Lindström
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.ALWAYS)
public class SamlAuthnRequestParameterModel {

  private String sp;

  private String idp;

  @JsonProperty("signature_option")
  private SignatureOption signatureOption = SignatureOption.OK_SIGNATURE;

  @JsonProperty("possible_request_bindings")
  private List<String> possibleRequestBindings;

  @JsonProperty("request_binding")
  private String requestBinding;

  @JsonProperty("relay_state")
  private String relayState;

  @JsonProperty("force_authn")
  private Boolean forceAuthn;

  @JsonProperty("is_passive")
  private Boolean isPassive;

  private String destination;

  @JsonProperty("issue_instant")
  private Instant issueInstant;

  private String issuer;

  @JsonProperty("name_id_policy")
  private NameIdPolicy nameIdPolicy;

  @JsonProperty("requested_authn_context")
  private RequestedAuthnContext requestedAuthnContext;

  @JsonProperty("possible_assertion_consumer_service_urls")
  private List<String> possibleAssertionConsumerServiceUrls;

  @JsonProperty("assertion_consumer_service_url")
  private String assertionConsumerServiceUrl;

  @JsonProperty("requested_principal_selection")
  private List<RequestedPrincipalSelectionValue> requestedPrincipalSelection;

  @JsonProperty("user_message_extension")
  private UserMessageExtension userMessageExtension;

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

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class RequestedAuthnContext {

    private List<String> uris;

    private String comparison;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class RequestedPrincipalSelectionValue {
    private String name;
    private String value;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class UserMessageExtension {

    @JsonProperty("mime_type")
    private String mimeType;

    private List<Message> messages;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class Message {
      @JsonProperty("lang_code")
      private String langCode;

      private String language;

      private String message;
    }
  }

  public enum SignatureOption {

    OK_SIGNATURE("ok_signature"),
    NO_SIGNATURE("no_signature"),
    OTHER_SIGNATURE("other_signature"),
    BAD_SIGNATURE("bad_signature");

    SignatureOption(final String label) {
      this.label = label;
    }

    private final String label;

    @JsonValue
    public String getLabel() {
      return this.label;
    }

    @JsonCreator
    public static SignatureOption forLabel(final String label) {
      for (final SignatureOption s : values()) {
        if (s.label.equalsIgnoreCase(label)) {
          return s;
        }
      }
      throw new IllegalArgumentException("Unknown value: " + label);
    }
  }

}
