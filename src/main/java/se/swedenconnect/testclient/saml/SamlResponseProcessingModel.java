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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectLocality;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingException;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseStatusErrorException;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationException;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author Martin Lindström
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.ALWAYS)
@Slf4j
public class SamlResponseProcessingModel {

  private static final Map<String, String> ATTRIBUTE_REGISTRY;

  static {
    final Map<String, String> m = new LinkedHashMap<>();

    m.put(AttributeConstants.ATTRIBUTE_NAME_SN, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN);
    m.put(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME);
    m.put(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME);
    m.put(AttributeConstants.ATTRIBUTE_NAME_GENDER, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GENDER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PREVIOUS_PERSONAL_IDENTITY_NUMBER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PREVIOUS_PERSONAL_IDENTITY_NUMBER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH);
    m.put(AttributeConstants.ATTRIBUTE_NAME_BIRTH_NAME, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_BIRTH_NAME);
    m.put(AttributeConstants.ATTRIBUTE_NAME_STREET, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_STREET);
    m.put(AttributeConstants.ATTRIBUTE_NAME_POST_OFFICE_BOX,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_POST_OFFICE_BOX);
    m.put(AttributeConstants.ATTRIBUTE_NAME_POSTAL_CODE, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_POSTAL_CODE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_L, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_L);
    m.put(AttributeConstants.ATTRIBUTE_NAME_C, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_C);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PLACE_OF_BIRTH, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PLACE_OF_BIRTH);
    m.put(AttributeConstants.ATTRIBUTE_NAME_COUNTRY_OF_CITIZENSHIP,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_COUNTRY_OF_CITIZENSHIP);
    m.put(AttributeConstants.ATTRIBUTE_NAME_COUNTRY_OF_RESIDENCE,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_COUNTRY_OF_RESIDENCE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_TELEPHONE_NUMBER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_TELEPHONE_NUMBER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_MOBILE, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_MOBILE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_MAIL, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_MAIL);
    m.put(AttributeConstants.ATTRIBUTE_NAME_O, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_O);
    m.put(AttributeConstants.ATTRIBUTE_NAME_OU, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_OU);
    m.put(AttributeConstants.ATTRIBUTE_NAME_ORGANIZATION_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_ORGANIZATION_IDENTIFIER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_ORG_AFFILIATION,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_ORG_AFFILIATION);
    m.put(AttributeConstants.ATTRIBUTE_NAME_TRANSACTION_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_TRANSACTION_IDENTIFIER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_AUTH_CONTEXT_PARAMS,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_AUTH_CONTEXT_PARAMS);
    m.put(AttributeConstants.ATTRIBUTE_NAME_USER_CERTIFICATE,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_USER_CERTIFICATE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_USER_SIGNATURE, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_USER_SIGNATURE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_AUTH_SERVER_SIGNATURE,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_AUTH_SERVER_SIGNATURE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_SAD, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SAD);
    m.put(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SIGNMESSAGE_DIGEST);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PRID, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PRID);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PRID_PERSISTENCE,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PRID_PERSISTENCE);
    m.put(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER_BINDING,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER_BINDING);
    m.put(AttributeConstants.ATTRIBUTE_NAME_MAPPED_PERSONAL_IDENTITY_NUMBER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_MAPPED_PERSONAL_IDENTITY_NUMBER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_EIDAS_PERSON_IDENTIFIER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_EIDAS_PERSON_IDENTIFIER);
    m.put(AttributeConstants.ATTRIBUTE_NAME_EIDAS_NATURAL_PERSON_ADDRESS,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_EIDAS_NATURAL_PERSON_ADDRESS);
    m.put(AttributeConstants.ATTRIBUTE_NAME_EMPLOYEE_HSA_ID,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_EMPLOYEE_HSA_ID);

    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PHONE_NUMBER_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PHONE_NUMBER_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_EMAIL_ADDRESS_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_EMAIL_ADDRESS_ATTRIBUTE_FRIENDLY_NAME);

    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_DATE_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);
    m.put(se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_GENDER_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_GENDER_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_ADDRESS_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_BIRTH_NAME_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME);
    m.put(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_REPRESENTATIVE_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME);

    ATTRIBUTE_REGISTRY = Collections.unmodifiableMap(m);
  }

  private List<String> errors;

  /** Error reported from the IdP. */
  @JsonProperty("idp_error")
  private boolean idpError = false;

  /** Whether the user cancelled the request. */
  private boolean cancelled = false;

  private String response;

  @JsonProperty("response_details")
  private ResponseDetails responseDetails;

  @JsonProperty("relay_state")
  private String relayState;

  private String assertion;

  @JsonProperty("assertion_details")
  private AssertionDetails assertionDetails;

  public SamlResponseProcessingModel(final ResponseProcessingResult result, final String relayState) {
    this.relayState = relayState;
    this.assignResponse(result.getResponse());
    this.assignAssertion(result.getAssertion());
  }

  public SamlResponseProcessingModel(final Exception ex, final String relayState) {

    this.relayState = relayState;
    if (ex instanceof final ResponseStatusErrorException statusException) {
      this.errors = List.of(statusException.getMessage());
      this.assignResponse(statusException.getResponse());
      this.idpError = true;
      this.cancelled = Optional.ofNullable(this.responseDetails)
          .map(ResponseDetails::getStatus)
          .map(ResponseDetails.SamlStatus::isCancel)
          .orElse(false);
    }
    else if (ex instanceof final ResponseProcessingException processingException) {
      if (processingException instanceof final ResponseValidationException responseValidationException) {
        this.errors = Optional.ofNullable(responseValidationException.getValidationErrors())
            .orElse(List.of(processingException.getMessage()));
      }
      else {
        this.errors = List.of(processingException.getMessage());
      }
      Optional.ofNullable(processingException.getResponse()).ifPresent(this::assignResponse);
      Optional.ofNullable(processingException.getAssertion()).ifPresent(this::assignAssertion);
    }
    else {
      this.errors = List.of(ex.getMessage());
    }
  }

  void assignResponse(final Response response) {
    this.responseDetails = new ResponseDetails(response);

    try {
      Element element = response.getDOM();
      if (element == null) {
        element = XMLObjectSupport.marshall(response);
      }
      this.response = SerializeSupport.prettyPrintXML(element);
    }
    catch (final Exception e) {
      this.response = "Failed to get serialize Response";
      log.error("Failed to serialize Response", e);
    }

  }

  void assignAssertion(final Assertion assertion) {
    this.assertionDetails = new AssertionDetails(assertion);

    try {
      Element element = assertion.getDOM();
      if (element == null) {
        element = XMLObjectSupport.marshall(assertion);
      }
      this.assertion = SerializeSupport.prettyPrintXML(element);
    }
    catch (final Exception e) {
      this.assertion = "Failed to get serialize Assertion";
      log.error("Failed to serialize Assertion", e);
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class ResponseDetails {

    @JsonProperty("response_id")
    private String responseId;

    private SamlStatus status;

    private String issuer;

    @JsonProperty("in_response_to")
    private String inResponseTo;

    @JsonProperty("issue_instant")
    private Instant issueInstant;

    private String destination;

    private boolean signed;

    private boolean encrypted;

    public ResponseDetails(final Response response) {
      this.responseId = response.getID();
      this.status = new SamlStatus(response.getStatus());
      this.issuer = Optional.ofNullable(response.getIssuer()).map(XSString::getValue).orElse(null);
      this.inResponseTo = response.getInResponseTo();
      this.issueInstant = response.getIssueInstant();
      this.destination = response.getDestination();
      this.signed = response.isSigned();
      this.encrypted = !response.getEncryptedAssertions().isEmpty();
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class SamlStatus {
      private List<String> code;
      private String message;

      public SamlStatus(final Status status) {
        this.code = new ArrayList<>();
        this.message = Optional.ofNullable(status.getStatusMessage())
            .map(XSString::getValue)
            .orElse(null);

        StatusCode sc = status.getStatusCode();
        while (sc != null) {
          this.code.add(sc.getValue());
          sc = sc.getStatusCode();
        }

      }

      @JsonIgnore
      public boolean isCancel() {
        return this.code != null && this.code.contains("http://id.elegnamnden.se/status/1.0/cancel");
      }
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.ALWAYS)
  public static class AssertionDetails {
    private String id;

    @JsonProperty("issue_instant")
    private Instant issueInstant;

    private String issuer;
    private boolean signed;

    private SamlSubject subject;

    private SamlConditions conditions;

    @JsonProperty("authentication_statement")
    private AuthenticationStatement authenticationStatement;

    @JsonProperty("attribute_statement")
    private List<SamlAttribute> attributeStatement;

    public AssertionDetails(final Assertion assertion) {
      this.id = assertion.getID();
      this.issueInstant = assertion.getIssueInstant();
      this.issuer = Optional.ofNullable(assertion.getIssuer()).map(XSString::getValue).orElse(null);
      this.signed = assertion.isSigned();
      this.subject = Optional.ofNullable(assertion.getSubject())
          .map(SamlSubject::new)
          .orElse(null);
      this.conditions = Optional.ofNullable(assertion.getConditions())
          .map(SamlConditions::new)
          .orElse(null);
      this.authenticationStatement = !assertion.getAuthnStatements().isEmpty()
          ? new AuthenticationStatement(assertion.getAuthnStatements().getFirst())
          : null;
      if (!assertion.getAttributeStatements().isEmpty()) {
        this.attributeStatement =
            assertion.getAttributeStatements().getFirst().getAttributes().stream()
                .map(SamlAttribute::new)
                .toList();
      }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class SamlSubject {

      @JsonProperty("name_id")
      private SamlNameId nameId;

      @JsonProperty("confirmation")
      private SamlConfirmation confirmation;

      public SamlSubject(final Subject subject) {
        this.nameId = Optional.ofNullable(subject.getNameID())
            .map(SamlNameId::new)
            .orElse(null);
        if (!subject.getSubjectConfirmations().isEmpty()) {
          this.confirmation = new SamlConfirmation(subject.getSubjectConfirmations().getFirst());
        }
      }

      @Data
      @NoArgsConstructor
      @AllArgsConstructor
      @JsonInclude(JsonInclude.Include.ALWAYS)
      public static class SamlNameId {
        private String value;
        private String format;
        @JsonProperty("name_qualifier")
        private String nameQualifier;
        @JsonProperty("sp_name_qualifier")
        private String spNameQualifier;

        public SamlNameId(final NameID nameId) {
          this.value = nameId.getValue();
          this.format = nameId.getFormat();
          this.nameQualifier = nameId.getNameQualifier();
          this.spNameQualifier = nameId.getSPNameQualifier();
        }
      }

      @Data
      @NoArgsConstructor
      @AllArgsConstructor
      @JsonInclude(JsonInclude.Include.ALWAYS)
      public static class SamlConfirmation {
        private String method;
        private String address;
        @JsonProperty("in_response_to")
        private String inResponseTo;
        @JsonProperty("not_before")
        private Instant notBefore;
        @JsonProperty("not_after")
        private Instant notAfter;
        private String recipient;

        public SamlConfirmation(final SubjectConfirmation sc) {
          this.method = sc.getMethod();
          if (sc.getSubjectConfirmationData() != null) {
            this.address = sc.getSubjectConfirmationData().getAddress();
            this.inResponseTo = sc.getSubjectConfirmationData().getInResponseTo();
            this.notBefore = sc.getSubjectConfirmationData().getNotBefore();
            this.notAfter = sc.getSubjectConfirmationData().getNotOnOrAfter();
            this.recipient = sc.getSubjectConfirmationData().getRecipient();
          }
        }
      }

    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class SamlConditions {
      @JsonProperty("not_before")
      private Instant notBefore;
      @JsonProperty("not_after")
      private Instant notAfter;
      private List<String> audiences;

      public SamlConditions(final Conditions conditions) {
        this.notBefore = conditions.getNotBefore();
        this.notAfter = conditions.getNotOnOrAfter();
        this.audiences = new ArrayList<>();
        conditions.getAudienceRestrictions()
            .forEach(r -> r.getAudiences().forEach(a -> this.audiences.add(a.getURI())));
      }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class AuthenticationStatement {
      @JsonProperty("authn_instant")
      private Instant authnInstant;
      @JsonProperty("subject_locality")
      private String subjectLocality;
      @JsonProperty("authn_context_class_ref")
      private String authnContextClassRef;

      public AuthenticationStatement(final AuthnStatement authnStatement) {
        this.authnInstant = authnStatement.getAuthnInstant();
        this.subjectLocality = Optional.ofNullable(authnStatement.getSubjectLocality())
            .map(SubjectLocality::getAddress)
            .orElse(null);
        this.authnContextClassRef = Optional.ofNullable(authnStatement.getAuthnContext())
            .map(AuthnContext::getAuthnContextClassRef)
            .map(XSURI::getURI)
            .orElse(null);

      }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public static class SamlAttribute {
      private String name;
      @JsonProperty("friendly_name")
      private String friendlyName;
      private String value;

      public SamlAttribute(final Attribute attribute) {
        this.name = attribute.getName();
        this.friendlyName = Optional.ofNullable(attribute.getFriendlyName())
            .orElseGet(() -> ATTRIBUTE_REGISTRY.get(this.name));
        this.value = AttributeUtils.getAttributeStringValue(attribute);
      }
    }

  }

}
