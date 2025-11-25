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

/**
 * State class for SAML.
 */
class SamlState extends State {

  /**
   * Constructor.
   *
   * @param localStorageKey the name for the key used for local storage
   * @param sessionStorageKey the name for the key used for session storage
   */
  constructor(localStorageKey, sessionStorageKey) {
    super(localStorageKey, sessionStorageKey);
  }

  /**
   * Returns the currently selected SP.
   *
   * @returns {string|null} The currently selected SP or null
   */
  getSelectedSp() {
    return this.get('selectedSp');
  }

  /**
   * Assigns the selected SP
   * @param sp the SP that was selected
   */
  setSelectedSp(sp) {
    this.set('selectedSp', sp, true);
  }

  /**
   * Returns the currently selected IdP.
   * @returns {string|null} The currently selected IdP or null
   */
  getSelectedIdp() {
    return this.get('selectedIdp');
  }

  /**
   * Assigns the selected IdP.
   * @param idp the IdP that was selected
   */
  setSelectedIdp(idp) {
    this.set('selectedIdp', idp, true);
  }

  /**
   * Returns the setup data (see SetupAuthentication).
   * @returns {SetupAuthentication|null} the setup data.
   */
  getSetupData() {
    return this.get('setupData');
  }

  /**
   * Assigns the setup data (see SetupAuthentication).
   * @param data the setup data.
   */
  setSetupData(data) {
    this.set('setupData', data);
  }

  /**
   * Gets the active authentication request data.
   * @returns {*} AuthnRequest data
   */
  getActiveAuthnRequest() {
    return this.get('authn_request_data');
  }

  /**
   * Stores the active AuthnRequest data
   * @param authnRequest the authentication request XML
   * @param relayState the relay state
   * @param parameters the parameters (from the AuthnRequest view)
   */
  setActiveAuthnRequest(authnRequest, relayState, parameters) {
    this.set('authn_request_data', { authn_request: authnRequest, relay_state: relayState, parameters: parameters });
  }

  /**
   * Gets the authentication result data.
   * @returns {*} authentication result data
   */
  getAuthnResult() {
    return this.get('authn_result');
  }

  /**
   * Assigns the authentication result data.
   * @param authnResult authentication result data
   */
  setAuthnResult(authnResult) {
    this.set('authn_result', authnResult);
  }
}

const SAML_STATE = new SamlState('sctc.saml', 'sctc.saml.session');

/**
 * Main class for SAML authentication.
 */
class SamlAuthentication {

  static SAML_STATE_SETUP = 'setup';
  static SAML_STATE_BUILD = 'build';
  static SAML_STATE_AUTHN = 'authn';
  static SAML_STATE_RESULT = 'result';

  /**
   * Sets up the SAML authentication view. The view is either loaded "fresh", or continues from a saved session state.
   */
  constructor() {
    this.setupAuthn = new SetupAuthentication(() => this.onSetupPhaseNext());
    this.authnRequestView = null;
    this.resultView = null;

    this.setupAuthn.init();
    this.setupAuthn.displaySetup();

    const state = this.getSessionState();

    if (state === SamlAuthentication.SAML_STATE_SETUP) {
      AuthnRequest.hide();
      AuthenticationResult.hide();
      return;
    }
    else {
      // If we are not in our initial state, we disable the view, i.e., we display it, but stick to the selected values.
      this.setupAuthn.disableSetup();
    }

    // We are in "build authentication request state" ...
    if (state === SamlAuthentication.SAML_STATE_BUILD) {
      this.activateAuthnRequestView();
      AuthenticationResult.hide();
      return;
    }

    // We are in authn or result "mode" ...
    //
    const authnRequestData = SAML_STATE.getActiveAuthnRequest();
    if (!authnRequestData) {
      // No session. Reset
      this.onRestart();
      return;
    }
    this.resultView = new AuthenticationResult(authnRequestData, () => this.onRestart());

    if (state === SamlAuthentication.SAML_STATE_AUTHN) {

      // Handle that we did not get saml_responseData ...
      if (!window.saml_responseData) {
        this.onRestart();
        return;
      }
      this.updateSessionState(SamlAuthentication.SAML_STATE_RESULT);
      this.resultView.verifyResponse(window.saml_responseData);

    }
    else { // SamlAuthentication.SAML_STATE_RESULT
      const resultData = SAML_STATE.getAuthnResult();
      if (!resultData) {
        this.onRestart();
        return;
      }
      this.resultView.displayResult(resultData);
      AuthenticationResult.scrollTo();
    }
  }

  /**
   * Scrolls to the active view. Called when selecting "SAML" in the main menu.
   */
  scrollToActiveView() {
    const state = this.getSessionState();
    if (state === SamlAuthentication.SAML_STATE_BUILD) {
      AuthnRequest.scrollTo();
    }
    else if (state === SamlAuthentication.SAML_STATE_RESULT) {
      AuthenticationResult.scrollTo();
    }
  }

  /**
   * Sets up the "build authentication view".
   */
  activateAuthnRequestView() {
    $.ajax({
      url: '/saml/authn/template',
      type: 'GET',
      data: {
        sp: SAML_STATE.getSelectedSp(),
        idp: SAML_STATE.getSelectedIdp()
      },
      success: (template) => {
        this.authnRequestView = new AuthnRequest(template, () => this.onRestart(),
            (pars) => this.onSendAuthnRequest(pars));
        this.authnRequestView.init();
        AuthnRequest.scrollTo();
      },
      error: (error) => {
        // TODO
        console.error("Failed to generate authentication request template: " + JSON.stringify(error));
      }
    });
  }

  /**
   * Is called when the Next-button is clicked in the setup-view.
   */
  onSetupPhaseNext() {
    this.setupAuthn.disableSetup();
    this.updateSessionState(SamlAuthentication.SAML_STATE_BUILD);
    this.activateAuthnRequestView();
  }

  /**
   * Is called when the authentication flow is restarted.
   */
  onRestart() {
    AuthnRequest.hide();
    this.authnRequestView = null;

    AuthenticationResult.hide();
    this.resultView = null;

    this.updateSessionState(SamlAuthentication.SAML_STATE_SETUP);
    this.setupAuthn.displaySetup();

    let mainDiv = $('#main-saml');
    let pos = mainDiv.offset().top;
    $('html, body').animate({ scrollTop: pos }, 'slow');
  }

  /**
   * Callback function that is invoked to generate an AuthnRequest and redirect the browser.
   * @param authnRequest the AuthnRequest parameters
   */
  onSendAuthnRequest(authnRequest) {

    $.ajax({
      url: '/saml/authn/generate',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(authnRequest),
      dataType: 'json',
      success: (response) => {
        this.updateSessionState(SamlAuthentication.SAML_STATE_AUTHN);

        const authnRequestPars = this.authnRequestView.getAuthnRequestParameters();
        authnRequestPars.id = response.id;
        authnRequestPars.issue_instant = response.issue_instant;

        SAML_STATE.setActiveAuthnRequest(
            response.authn_request, response.relay_state, authnRequestPars);
        this.authnRequestView = null;

        if (response.method === "POST") {
          postBrowser(response.url, response.parameters);
        }
        else {
          redirectBrowser(response.url);
        }
      },
      error: (error) => {
        // TODO: Display error and return to view ...
        console.error("Failed to generate SAML AuthnRequest: " + JSON.stringify(error));
      }

    });
  }

  /**
   * Gets the current session state. It can be 'setup', 'build', 'authn' and 'result'.
   * @returns {string} the state
   */
  getSessionState() {
    let state = SAML_STATE.get('state');
    if (!state) {
      SAML_STATE.set('state', SamlAuthentication.SAML_STATE_SETUP);
      return SamlAuthentication.SAML_STATE_SETUP;
    }
    return state;
  }

  /**
   * Updates the SAML session state.
   * @param state the new state
   */
  updateSessionState(state) {
    SAML_STATE.set('state', state, false, true);
  }

}

class AuthenticationResult {

  constructor(authnRequestData, onRestartCallback) {
    this.restartCallback = onRestartCallback;
    this.authnRequestData = authnRequestData;

    $('#saml-authn-result-restart-button').click(() => {
      this.restartCallback();
    });

    $('#saml-authn-result-view-authnrequest').click(() => {
      codeViewer.displayXml('Authentication Request', this.authnRequestData.authn_request);
    });

    $('#saml-authn-result-view-authnrequest-details').click((event) => {
      $(event.target).hide();
      if (this.authnRequestData.parameters) {
        this.displayAuthnRequestDetails(this.authnRequestData.parameters);
        $('#saml-authn-result-authnrequest-details').show();
      }
    });
  }

  static hide() {
    $('#saml-authn-result').hide();
  }

  static scrollTo() {
    let resultDiv = $('#saml-authn-result');
    resultDiv.show();
    let pos = resultDiv.offset().top - 38;
    $('html, body').animate({ scrollTop: pos }, 'slow');
  }

  verifyResponse(responseData) {

    const verifyInput = {
      sp: SAML_STATE.getSelectedSp(),
      authn_request: this.authnRequestData.authn_request,
      sent_relay_state: this.authnRequestData.relay_state,
      response_data: responseData
    };

    $.ajax({
      url: '/saml/authn/verify',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(verifyInput),
      dataType: 'json',
      success: (result) => {
        SAML_STATE.setAuthnResult(result);
        this.displayResult(result);
        AuthenticationResult.scrollTo();
      },
      error: (error) => {
        console.error("Failed to process SAML response: " + JSON.stringify(error));
        const result = {
          errors: [ "Error while processing SAML response" ]
        };
        SAML_STATE.setAuthnResult(result);
        this.displayResult(result);
      }
    });
  }

  displayResult(resultData) {

    const resultErrorDiv = $('#saml-authn-result-idp-error');
    resultErrorDiv.removeClass('bg-secondary bg-warning bg-danger');

    if (resultData.errors && resultData.errors.length > 0) {
      const heading = resultErrorDiv.find('.card-header');
      if (resultData.idp_error) {
        heading.text("IdP Error Status");
        if (resultData.cancelled) {
          resultErrorDiv.addClass('bg-secondary');
        }
        else {
          resultErrorDiv.addClass('bg-warning');
        }
      }
      else {
        heading.text("Response Processing Error");
        resultErrorDiv.addClass('bg-danger');
      }
      const bodyDiv = resultErrorDiv.find('.card-body');
      for (let e of resultData.errors) {
        bodyDiv.append($('<p>', {
          class: 'card-text',
          text: e
        }));
      }
      resultErrorDiv.show();
    }
    else {
      resultErrorDiv.hide();
    }

    const viewResponseButton = $('#saml-authn-result-view-response');
    if (resultData.response) {
      viewResponseButton.click(() => {
        codeViewer.displayXml('SAML Response', resultData.response);
      });
    }
    else {
      viewResponseButton.hide();
    }

    const responseDiv = $('#saml-authn-result-response');
    if (resultData.response_details) {
      const tableDiv = responseDiv.find('tbody');

      tableDiv.append(this.createRow("Relay State", resultData.relay_state));
      tableDiv.append(this.createRow("ID", resultData.response_details.response_id));
      tableDiv.append(this.createRow("Status", resultData.response_details.status
          ? [
            ...(resultData.response_details.status.code ? resultData.response_details.status.code.map(c => [ c ]) : []),
            ...(resultData.response_details.status.message ? [ [ resultData.response_details.status.message ] ] : []) ]
          : null));
      tableDiv.append(this.createRow("Issuer", resultData.response_details.issuer));
      tableDiv.append(this.createRow("In Response To", resultData.response_details.in_response_to));
      tableDiv.append(this.createRow("Issue Instant", resultData.response_details.issue_instant));
      tableDiv.append(this.createRow("Destination", resultData.response_details.destination));
      tableDiv.append(this.createRow("Is Signed?", resultData.response_details.signed ? 'Yes' : 'No'));
      tableDiv.append(this.createRow("Encrypted Assertion?", resultData.response_details.encrypted ? 'Yes' : 'No'));

      responseDiv.show();
    }
    else {
      responseDiv.hide();
    }

    const viewAssertionButton = $('#saml-authn-result-view-assertion');
    if (resultData.assertion) {
      viewAssertionButton.click(() => {
        codeViewer.displayXml('Assertion', resultData.assertion);
      });
    }
    else {
      viewAssertionButton.hide();
    }

    const assertionDiv = $('#saml-authn-result-assertion');
    if (resultData.assertion_details) {
      const tableDiv = $('#body-assertion');

      tableDiv.append(this.createRow("ID", resultData.assertion_details.id));
      tableDiv.append(this.createRow("Issue Instant", resultData.assertion_details.issue_instant));
      tableDiv.append(this.createRow("Is Signed?", resultData.assertion_details.signed ? 'Yes' : 'No'));
      tableDiv.append(this.createRow("Issuer", resultData.assertion_details.issuer));
      const subjectNameID = resultData.assertion_details.subject && resultData.assertion_details.subject.name_id;
      tableDiv.append(this.createRow("Subject | NameID", subjectNameID
          ? [ [ subjectNameID.value || "Name not assigned" ],
            [ "Format", subjectNameID.format ],
            [ "Name qualifier", subjectNameID.name_qualifier ],
            [ "SP name qualifier", subjectNameID.sp_name_qualifier ], ]
          : null));
      const confirmation = resultData.assertion_details.subject && resultData.assertion_details.subject.confirmation;
      tableDiv.append(this.createRow("Subject | Confirmation", confirmation
          ? [ [ "Method", confirmation.method ],
            [ "Address", confirmation.address ],
            [ "In response to", confirmation.in_response_to ],
            [ "Not before", confirmation.not_before ],
            [ "Not on or after", confirmation.not_after ],
            [ "Recipient", confirmation.recipient ] ]
          : null));
      const conditions = resultData.assertion_details.conditions;
      tableDiv.append(this.createRow("Conditions", conditions
          ? [ [ "Not before", conditions.not_before ],
            [ "Not on or after", conditions.not_after ],
            [ "Audience restriction(s)", conditions.audiences ? conditions.audiences.join(', ') : null ] ]
          : null));
      const authnStatement = resultData.assertion_details.authentication_statement;
      tableDiv.append(this.createRow("Authentication Statement", authnStatement
          ? [ [ "Authentication instant", authnStatement.authn_instant ],
            [ "Subject locality", authnStatement.subject_locality ],
            [ "Authentication Context Class Ref", authnStatement.authn_context_class_ref ] ]
          : null));

      const attributesDiv = $('#body-attributes');
      const attributes = resultData.assertion_details.attribute_statement;
      if (attributes) {
        for (let attr of attributes) {
          attributesDiv.append($('<tr>')
              .append($('<td>', {
                class: 'table-text',
                text: attr.name || '-'
              }))
              .append($('<td>', {
                class: 'table-text',
                text: attr.friendly_name || '-'
              }))
              .append($('<td>', {
                class: 'table-text',
                text: attr.value || '-'
              }))
          );
        }
      }
      else {
        tableDiv.append(this.createRow("Attribute Statement", null));
        $('#assertions-table').hide();
      }

      assertionDiv.show();
    }
    else {
      assertionDiv.hide();
    }

  }

  /**
   * Displays authentication request details
   * @param pars the request parameters (as built in the Authentication Build view)
   */
  displayAuthnRequestDetails(pars) {
    const detailsDiv = $('#saml-authn-result-authnrequest-details');
    const detailsTable = detailsDiv.find('tbody');

    detailsTable.append(this.createRow("Requesting SP", pars.sp));
    detailsTable.append(this.createRow("Identity Provider", pars.idp));
    detailsTable.append(this.createRow("Relay State", pars.relay_state));
    detailsTable.append(this.createRow("Request Binding", pars.request_binding));
    detailsTable.append(this.createRow("Signature Status", pars.signature_option === 'no_signature'
        ? "Not signed"
        : pars.signature_option === 'other_signature' ? "Signed with \"wrong\" key/certificate" : "Signed"));
    detailsTable.append(this.createRow("ID", pars.id));
    detailsTable.append(this.createRow("Issue Instant", pars.issue_instant));
    detailsTable.append(this.createRow("Force Authentication", pars.force_authn));
    detailsTable.append(this.createRow("Is Passive", pars.is_passive));
    detailsTable.append(this.createRow("Assertion Consumer Service URL", pars.assertion_consumer_service_url));
    detailsTable.append(this.createRow("Destination", pars.destination));
    detailsTable.append(this.createRow("Issuer", pars.issuer));
    if (pars.name_id_policy) {
      detailsTable.append(this.createRow("NameID Policy", [ [ "Format", pars.name_id_policy.format ],
        [ "Allow create", pars.name_id_policy.allow_create ],
        [ "SP name qualifier", pars.name_id_policy.sp_name_qualifier ] ]));
    }
    else {
      detailsTable.append(this.createRow("NameID Policy", null));
    }
    detailsTable.append(this.createRow("Requested Authentication Context",
        pars.requested_authn_context
            ? (pars.requested_authn_context.uris && pars.requested_authn_context.uris.length > 0
                ? pars.requested_authn_context.uris.map(uri => [ uri ])
                : [ [ "No AuthnContextContextClassRef URIs given" ] ])
                .concat([ [ "Comparison", pars.requested_authn_context.comparison ] ])
            : null));
    detailsTable.append(this.createRow("Scoping | Requester IDs",
        pars.scoping ? pars.scoping.requester_ids.map(ri => [ ri ]) : null));
    detailsTable.append(this.createRow("Scoping | IDP List",
        pars.scoping ? pars.scoping.idp_list.map(idp => [ idp ]) : null));
    detailsTable.append(this.createRow("Requested Principal Selection",
        pars.requested_principal_selection && pars.requested_principal_selection.length > 0
            ? pars.requested_principal_selection.map(rps => [ rps.name, rps.value ])
            : null));

    detailsTable.append(this.createRow("User Message Extension", pars.user_message_extension
        ? [ ...pars.user_message_extension.messages.map(m =>
            [ m.lang_code, m.message ]), [ "MIME type", pars.user_message_extension.mime_type ] ]
        : null));

    detailsTable.append(this.createRow("Sign Message Extension", pars.sign_message
        ? [ [ pars.sign_message.message ],
          [ "MIME type", pars.sign_message.mime_type ],
          [ "Encrypted", pars.sign_message.encrypt ],
          [ "Display entity", pars.sign_message.display_entity ],
          [ "Must show flag", pars.sign_message.must_show ] ]
        : null));

    detailsDiv.show();
  }

  createRow(title, contents) {

    let html = "";
    if (Array.isArray(contents)) {
      html = contents.map(pair => pair.length === 1 ? pair[0] : `${pair[0]}: ${pair[1] || 'Not assigned'}`)
          .join('<br/>');
    }
    else {
      html = contents;
    }

    return $('<tr>')
        .append($('<th>', {
          scope: 'row',
          class: 'table-text',
          text: title
        }))
        .append($('<td>', {
          class: 'table-text',
          html: html || "Not assigned"
        }));
  }

}

/**
 * Class that handles the setup-phase.
 */
class SetupAuthentication {

  /**
   * Constructor.
   */
  constructor(onNextCallback) {
    this.nextCallback = onNextCallback;
    this.infoCache = SAML_STATE.getSetupData() || null;
  }

  /**
   * Initializes the setup section.
   */
  init() {

    const self = this;

    $('#saml-sp-select').change(function() {
      let selectedSp = $(this).val() === 'none' ? null : $(this).val();
      SAML_STATE.setSelectedSp(selectedSp);
      self.displaySelectedSp(selectedSp);
    });

    $('#sp-view-metadata').click(function() {
      let entityId = $(this).val();
      $.ajax({
        url: '/saml/sp/metadata',
        type: 'GET',
        data: {
          sp: entityId
        },
        success: (metadata) => {
          codeViewer.displayXml(entityId, metadata);
        },
        error: (error) => {
          console.error("Failed to get SP metadata: " + JSON.stringify(error));
        }
      });
    });

    $('#saml-idp-select').change(function() {
      let selectedIdp = $(this).val() === 'none' ? null : $(this).val();
      SAML_STATE.setSelectedIdp(selectedIdp);
      self.displaySelectedIdp(selectedIdp);
    });

    $('#idp-view-metadata').click(function() {
      let entityId = $(this).val();
      $.ajax({
        url: '/saml/idp/metadata',
        type: 'GET',
        data: {
          idp: entityId
        },
        success: (metadata) => {
          codeViewer.displayXml(entityId, metadata);
        },
        error: (error) => {
          console.error("Failed to get IdP metadata: " + JSON.stringify(error));
        }
      });
    });

    $('#saml-authn-next-button').click(function() {
      self.nextCallback();
    });

  }

  /**
   * Displays the setup view where the user selects SP and IdP for authentication.
   */
  displaySetup() {

    if (this.infoCache) {
      this.displaySps(this.infoCache.sps);
      this.displayIdps(this.infoCache.idps);
    }
    else {
      $.ajax({
        url: '/saml/authn/info',
        type: 'GET',
        success: (info) => {
          this.infoCache = info;
          SAML_STATE.setSetupData(this.infoCache);
          this.displaySps(this.infoCache.sps);
          this.displayIdps(this.infoCache.idps);
        },
        error: (error) => {
          console.error("Failed to get SP and IdP info: " + JSON.stringify(error));
          this.displaySps([]);
          this.displayIdps([]);
        }
      });
    }
    $('#saml-authn-next-button-div').show();
  }

  /**
   * Disables the setup view.
   */
  disableSetup() {
    $('#saml-sp-select').prop('disabled', true);
    $('#saml-idp-select').prop('disabled', true);
    $('#saml-authn-next-button').prop('disabled', true);
    $('#saml-authn-next-button-div').hide();
  }

  /**
   * Displays the different SP:s that are available
   * @param spInfo a list of SP info
   */
  displaySps(spInfo) {
    let spSelect = $('#saml-sp-select');
    spSelect.prop('disabled', false);
    if (spSelect.find('option').length === 0) {
      $('#sp-info').hide();
      spSelect.append(new Option("--- Select SP ---", "none", true, false));
      for (const sp of spInfo) {
        spSelect.append(new Option(sp.entity_id, sp.entity_id, false, false));
      }
    }
    let selectedSp = SAML_STATE.getSelectedSp();
    if (selectedSp) {
      spSelect.val(selectedSp);
      this.displaySelectedSp(selectedSp);
    }
  }

  /**
   * Displays info about the selected SP.
   * @param entityId the SP entity ID or "none"/null
   */
  displaySelectedSp(entityId) {
    if (!entityId || entityId === "none") {
      $('#sp-info').hide();
      $('#saml-authn-next-button').prop('disabled', true);
    }
    else {
      for (const sp of this.infoCache.sps) {
        if (sp.entity_id === entityId) {
          $('#sp-description').text(sp.description);
          let spUrl = $('#sp-metadata-url');
          spUrl.attr('href', sp.metadata_url);
          spUrl.text(sp.metadata_url);
          $('#sp-view-metadata').attr('value', sp.entity_id);
          $('#sp-info').show();

          if (SAML_STATE.getSelectedIdp()) {
            $('#saml-authn-next-button').prop('disabled', false);
          }
          break;
        }
      }
    }
  }

  /**
   * Displays the IdP:s that are available.
   * @param idpInfo a list of IdP info
   */
  displayIdps(idpInfo) {
    let idpSelect = $('#saml-idp-select');
    idpSelect.prop('disabled', false);
    if (idpSelect.find('option').length === 0) {
      $('#idp-info').hide();
      idpSelect.append(new Option("--- Select IdP ---", "none", true, false));
      for (const idp of idpInfo) {
        idpSelect.append(new Option(idp.entity_id, idp.entity_id, false, false));
      }
    }
    let selectedIdp = SAML_STATE.getSelectedIdp();
    if (selectedIdp) {
      idpSelect.val(selectedIdp);
      this.displaySelectedIdp(selectedIdp);
    }
  }

  /**
   * Displays info about the selected IdP.
   * @param entityId the IdP entity ID or "none"/null
   */
  displaySelectedIdp(entityId) {
    if (!entityId || entityId === "none") {
      $('#idp-info').hide();
      $('#saml-authn-next-button').prop('disabled', true);
    }
    else {
      for (const idp of this.infoCache.idps) {
        if (idp.entity_id === entityId) {
          $('#idp-displayname').text(idp.display_name);
          $('#idp-description').text(idp.description);
          $('#idp-view-metadata').attr('value', idp.entity_id);
          $('#idp-info').show();

          if (SAML_STATE.getSelectedSp()) {
            $('#saml-authn-next-button').prop('disabled', false);
          }

          break;
        }
      }
    }
  }
}

/**
 * Represents the SAML AuthnRequest regarding the HTML elements that are displayed.
 */
class AuthnRequest {

  /**
   * Constructor that initializes all elements for the SAML AuthnRequest.
   * @param template the AuthnRequest template
   * @param onRestartCallback callback to invoke when flow is restarted
   * @param onSendAuthnRequestCallback callback to invoked when "Send request" is clicked
   */
  constructor(template, onRestartCallback, onSendAuthnRequestCallback) {
    this.pars = template;
    this.restartCallback = onRestartCallback;
    this.sendAuthnRequestCallback = onSendAuthnRequestCallback;
  }

  /**
   * Initializes the AuthnRequest builder view.
   */
  init() {
    this.initRequestBindings(this.pars.request_binding, this.pars.possible_request_bindings);
    this.initRelayState(this.pars.relay_state);
    this.initSignatureOptions(this.pars.signature_option);
    this.initForceAuthn(this.pars.force_authn);
    this.initIsPassive(this.pars.is_passive);
    this.initDestination(this.pars.destination, this.pars.redirect_destination, this.pars.post_destination);
    this.initIssueInstant();
    // advanced

    $('#saml-advanced-authn-request-button').click(function() {
      $('#saml-advanced-authn-request-button-div').hide();
      $('#saml-advanced-authn-request').show();
    });

    this.initIssuer(this.pars.issuer);
    this.initNameIdPolicy(this.pars.name_id_policy);
    this.initRequestedAuthnContext(this.pars.requested_authn_context);
    this.initAcs(this.pars.assertion_consumer_service_url, this.pars.possible_assertion_consumer_service_urls);
    this.initRequestedPrincipalSelection();
    this.initUserMessage(this.pars.user_message_extension);
    this.initScoping();
    this.initSignMessage(this.pars.idp, this.pars.sign_message);

    $('#saml-request-restart-button').click(() => {
      this.restartCallback();
    });

    $('#saml-request-submit-button').click(() => {
      this.sendAuthnRequestCallback(this.readAndGetAuthnRequestParameters());
    });
  }

  static hide() {
    $('#saml-build-authn').hide();
  }

  static scrollTo() {
    let samlBuildAuthnDiv = $('#saml-build-authn');
    samlBuildAuthnDiv.show();
    let pos = samlBuildAuthnDiv.offset().top - 38;
    $('html, body').animate({ scrollTop: pos }, 'slow');
  }

  getAuthnRequestParameters() {
    return this.pars;
  }

  /**
   * Updates the authentication request view and returns the parameters that (may) have been modified by the user.
   * @returns {any} AuthnRequest parameters
   */
  readAndGetAuthnRequestParameters() {
    this.pars.request_binding = this.getRequestBinding();
    this.pars.relay_state = this.getRelayState();
    this.pars.signature_option = this.getSignatureOption();
    this.pars.force_authn = this.getForceAuthn();
    this.pars.is_passive = this.getIsPassive();
    this.pars.destination = this.getDestination();
    this.pars.issue_instant = this.getIssueInstant();
    this.pars.issuer = this.getIssuer();
    this.pars.name_id_policy = this.getNameIdPolicy();
    this.pars.requested_authn_context = this.getRequestedAuthnContext();
    this.pars.assertion_consumer_service_url = this.getAcs();
    this.pars.requested_principal_selection = this.getRequestedPrincipalSelection();
    this.pars.user_message_extension = this.getUserMessage();
    this.pars.scoping = this.getScoping();
    this.pars.sign_message = this.getSignMessage();
    return this.pars;
  }

  /**
   * Utility method that given an input element gets the contents.
   * @param elm the input element
   * @returns {null|string} the contents or null
   */
  static getValueFromInput(elm) {
    let value = elm.val().trim();
    return value === '' ? null : value;
  }

  static setRadioButtonTrueFalseExclude(radio, value) {
    if (value === true) {
      $('input[name="' + radio + '"][value="true"]').prop('checked', true);
    }
    else if (value === false) {
      $('input[name="' + radio + '"][value="false"]').prop('checked', true);
    }
    else {
      $('input[name="' + radio + '"][value="exclude"]').prop('checked', true);
    }
  }

  static getRadioButtonTrueFalseExclude(radio) {
    let val = $('input[name="' + radio + '"]:checked').val();
    if (val === "true") {
      return true;
    }
    else if (val === "false") {
      return false;
    }
    else {
      return null;
    }
  }

  initRequestBindings(binding, possibleValues) {
    const samlRequestBindingSelect = $('#saml-request-binding-select');
    samlRequestBindingSelect.empty();
    for (let b of possibleValues) {
      let rb = b === binding;
      samlRequestBindingSelect.append(new Option(b, b, false, rb));
    }
  }

  getRequestBinding() {
    return $('#saml-request-binding-select').val();
  }

  initRelayState(rs) {
    $('#saml-request-relaystate-input').val(rs || '');
  }

  getRelayState() {
    return AuthnRequest.getValueFromInput($('#saml-request-relaystate-input'));
  }

  initSignatureOptions(opt) {
    let value = opt || 'ok_signature';
    $('input[name="saml-request-signature-radio"][value="' + value + '"]').prop('checked', true);
  }

  getSignatureOption() {
    return $('input[name="saml-request-signature-radio"]:checked').val();
  }

  initForceAuthn(fa) {
    AuthnRequest.setRadioButtonTrueFalseExclude("saml-request-forceauthn", fa);
  }

  getForceAuthn() {
    return AuthnRequest.getRadioButtonTrueFalseExclude("saml-request-forceauthn");
  }

  initIsPassive(ip) {
    AuthnRequest.setRadioButtonTrueFalseExclude("saml-request-ispassive", ip);
  }

  getIsPassive() {
    return AuthnRequest.getRadioButtonTrueFalseExclude("saml-request-ispassive");
  }

  initDestination(dest, redirectUrl, postUrl) {
    const destination = $('#saml-request-destination')
    destination.val(dest || '');

    $('#saml-request-binding-select').change((event) => {
      const binding = event.target.value;
      if (binding === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" && redirectUrl) {
        destination.val(redirectUrl);
      }
      else if (binding === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" && postUrl) {
        destination.val(postUrl);
      }
    });
  }

  getDestination() {
    return AuthnRequest.getValueFromInput($('#saml-request-destination'));
  }

  initIssueInstant() {
    let issueInstantInput = $('#saml-request-issueinstant');
    issueInstantInput.val('');

    $('#saml-request-issueinstant-button').click(function() {
      issueInstantInput.val(new Date().toISOString());
      $(this).hide();
    });
  }

  getIssueInstant() {
    return AuthnRequest.getValueFromInput($('#saml-request-issueinstant'));
  }

  /**
   * Initializes the optional issuer element.
   *
   * @param issuer {string} the SAML issuer
   */
  initIssuer(issuer) {
    let issuerCheckbox = $('#saml-request-issuer-present');
    let issuerRow = $('#saml-request-issuer-row');
    let issuerInput = $('#saml-request-issuer');
    if (issuer) {
      issuerInput.val(issuer);
      issuerCheckbox.prop('checked', true);
      issuerRow.show();
    }
    else {
      issuerInput.val('');
      issuerCheckbox.prop('checked', false);
      issuerRow.hide();
    }

    issuerCheckbox.change(function() {
      issuerRow.toggle(this.checked);
    });
  }

  /**
   * Gets the value from the issuer element.
   * @returns {string|null} the issuer value or null.
   */
  getIssuer() {
    if ($('#saml-request-issuer-present').prop('checked')) {
      return AuthnRequest.getValueFromInput($('#saml-request-issuer'));
    }
    else {
      return null;
    }
  }

  static NAME_ID_FORMATS = [
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  ];

  /**
   * Initializes the NameID Policy element.
   * @param nip the NameID policy object
   */
  initNameIdPolicy(nip) {
    let nipCheckbox = $('#saml-request-nip-present');
    let nipFormatSelect = $('#saml-request-nip-format');
    let nipDiv = $('#saml-request-nip-div');

    for (let format of AuthnRequest.NAME_ID_FORMATS) {
      nipFormatSelect.append(new Option(format, format));
    }
    nipFormatSelect.append(new Option("-- Attribute not assigned --", "exclude"));

    if (nip) {
      nipFormatSelect.val(nip.format || '');
      AuthnRequest.setRadioButtonTrueFalseExclude("saml-request-nip-ac", nip.allow_create);
      $('#saml-request-nip-spnq').val(nip.sp_name_qualifier || '');

      nipCheckbox.prop('checked', true);
      nipDiv.show();
    }
    else {
      nipFormatSelect.val('exclude');
      AuthnRequest.setRadioButtonTrueFalseExclude("saml-request-nip-ac", null);
      $('#saml-request-nip-spnq').val('');

      nipCheckbox.prop('checked', false);
      nipDiv.hide();
    }

    nipCheckbox.change(function() {
      nipDiv.toggle(this.checked);
    });

  }

  /**
   * Gets the NameID policy values assigned.
   * @returns {{}|null} the NameID Policy object or null
   */
  getNameIdPolicy() {
    if ($('#saml-request-nip-present').prop('checked')) {
      let policy = {};
      policy.format = $('#saml-request-nip-format').val();
      if (policy.format === "exclude") {
        policy.format = null;
      }
      policy.allow_create = AuthnRequest.getRadioButtonTrueFalseExclude("saml-request-nip-ac");
      policy.sp_name_qualifier = AuthnRequest.getValueFromInput($('#saml-request-nip-spnq'));
      return policy;
    }
    else {
      return null;
    }
  }

  static AUTHN_CONTEXT_CLASS_REF_URIS = [
    "http://id.elegnamnden.se/loa/1.0/loa1",
    "http://id.elegnamnden.se/loa/1.0/loa2",
    "http://id.swedenconnect.se/loa/1.0/loa2-nonresident",
    "http://id.swedenconnect.se/loa/1.0/uncertified-loa2",
    "http://id.elegnamnden.se/loa/1.0/loa3",
    "http://id.swedenconnect.se/loa/1.0/loa3-nonresident",
    "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
    "http://id.elegnamnden.se/loa/1.0/loa4",
    "http://id.swedenconnect.se/loa/1.0/loa4-nonresident",
    "http://id.elegnamnden.se/loa/1.0/eidas-low",
    "http://id.elegnamnden.se/loa/1.0/eidas-nf-low",
    "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-low",
    "http://id.elegnamnden.se/loa/1.0/eidas-sub",
    "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
    "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-sub",
    "http://id.elegnamnden.se/loa/1.0/eidas-high",
    "http://id.elegnamnden.se/loa/1.0/eidas-nf-high",
    "http://id.swedenconnect.se/loa/1.0/uncertified-eidas-high",
    "http://eidas.europa.eu/LoA/test"
  ];


  static addSelectedAuthnContextClassUri(list, uri) {
    if (list.children("li").length === 1) {
      let firstChild = list.find('li:first');
      if (firstChild.text().trim().startsWith('--')) {
        firstChild.remove();
      }
    }
    let liElm = $('<li>')
        .addClass('list-group-item d-flex justify-content-between align-items-center')
        .append($('<span>').text(uri))
        .append($('<button>').attr('type', 'button').addClass('btn-close'));
    list.append(liElm);
  }

  /**
   * Initializes the Requested Authn Context element.
   * @param rac the RAC object
   */
  initRequestedAuthnContext(rac) {
    let samlRequestRacCheckbox = $('#saml-request-rac-present');
    let samlRequestRacDiv = $('#saml-request-rac-div');

    let samlRequestRacList = $('#saml-request-rac-list');
    let samRequestRacAddDiv = $('#saml-request-rac-drop-div');
    let samlRequestRacCustomDiv = $('#saml-request-rac-custom-div');

    let samlRequestRacComparisonSelect = $('#saml-request-rac-comparison-select');

    let assignedUris = [];
    let comparison = null;

    if (rac) {
      assignedUris = rac.uris;
      comparison = rac.comparison;
    }

    samlRequestRacList.empty();
    for (let uri of assignedUris) {
      AuthnRequest.addSelectedAuthnContextClassUri(samlRequestRacList, uri);
    }
    if (assignedUris.length === 0) {
      samlRequestRacList.append($('<li>')
          .text("-- No URIs assigned --")
          .addClass('list-group-item d-flex justify-content-between align-items-center'));
    }

    samRequestRacAddDiv.empty();
    for (let uri of AuthnRequest.AUTHN_CONTEXT_CLASS_REF_URIS) {
      let option = $('<a>', {
        href: 'javascript:void(0)',
        class: 'dropdown-item',
        'data-pse-attr': uri,
        text: uri,
        click: function(event) {
          event.preventDefault();

          if ($(this).hasClass('disabled')) {
            return;
          }

          samlRequestRacCustomDiv.hide();
          AuthnRequest.addSelectedAuthnContextClassUri(samlRequestRacList, uri);
          $(this).addClass('disabled');
        }
      });

      if (assignedUris.includes(uri)) {
        option.addClass('disabled');
      }
      samRequestRacAddDiv.append(option);
    }
    samRequestRacAddDiv.append($('<a>', {
      href: 'javascript:void(0)',
      class: 'dropdown-item',
      'data-pse-attr': 'other',
      text: "Enter other URI ...",
      click: function(event) {
        event.preventDefault();
        samlRequestRacCustomDiv.show();
      }
    }));

    samlRequestRacComparisonSelect.val(comparison || 'exclude');

    if (rac) {
      samlRequestRacCheckbox.prop('checked', true);
      samlRequestRacDiv.show();
    }
    else {
      samlRequestRacCheckbox.prop('checked', false);
      samlRequestRacDiv.hide();
    }

    samlRequestRacCheckbox.change(function() {
      samlRequestRacDiv.toggle(this.checked);
    });

    samlRequestRacList.on('click', 'button.btn-close', function() {
      let ul = $(this).closest('ul');
      $(this).closest('li').remove();

      let uri = $(this).closest('li').find('span').text();

      let link = samRequestRacAddDiv.find('a[data-pse-attr="' + uri + '"]');
      if (link.length > 0) {
        link.removeClass('disabled');
      }

      if (ul.children('li').length === 0) {
        ul.append($('<li>')
            .text("-- No URIs assigned --")
            .addClass('list-group-item d-flex justify-content-between align-items-center'));
      }
    });

    $('#saml-request-rac-custom-button').click(function() {
      let samlRequestRacCustom = $('#saml-request-rac-custom');
      let uri = samlRequestRacCustom.val().trim();
      if (uri !== '') {
        AuthnRequest.addSelectedAuthnContextClassUri(samlRequestRacList, uri);
        samlRequestRacCustom.val('');
        samlRequestRacCustomDiv.hide();
      }
    });
  }

  /**
   * Gets the Requested Authn Context settings.
   * @returns {{}|null} a RAC object or null
   */
  getRequestedAuthnContext() {
    if ($('#saml-request-rac-present').prop('checked')) {
      let uris = [];
      $('#saml-request-rac-list li span').each(function() {
        uris.push($(this).text());
      });
      let rac = {};
      rac.uris = uris;
      rac.comparison = $('#saml-request-rac-comparison-select').val();
      if (rac.comparison === 'exclude') {
        rac.comparison = null;
      }
      return rac;
    }
    else {
      return null;
    }
  }

  /**
   * Initializes the Assertion Consumer Service URL element.
   * @param acs the ACS
   * @param possibleValues the possible URLs to choose from
   */
  initAcs(acs, possibleValues) {
    let acsSelect = $('#saml-request-acs-select');
    let acsCustomInput = $('#saml-request-acs-custom');
    let acsCustomDiv = $('#saml-request-acs-custom-div')

    acsSelect.empty();
    if (possibleValues.length) {
      for (let uri of possibleValues) {
        acsSelect.append(new Option(uri, uri));
      }
    }
    acsSelect.append(new Option("Enter other URL ...", "add", false, false));
    acsSelect.append(new Option("-- Not assigned --", "exclude", true, true));
    if (acs) {
      let opt = acsSelect.find('option[value="' + acs + '"]');
      opt.prop('selected', true);
    }
    acsCustomDiv.hide();

    acsSelect.change(function() {
      let selectedOption = $(this).find('option:selected');

      if (selectedOption.val() === 'add') {
        acsCustomDiv.show();
      }
      else {
        acsCustomDiv.hide();
        acsCustomInput.val('');
      }
    });

  }

  /**
   * Gets the Assertion Consumer Service URL.
   * @returns {string|null} the URL or null
   */
  getAcs() {
    let acsSelect = $('#saml-request-acs-select').val();
    if (acsSelect === 'add') {
      return AuthnRequest.getValueFromInput($('#saml-request-acs-custom'));
    }
    else if (acsSelect === 'exclude') {
      return null;
    }
    else {
      return acsSelect;
    }
  }

  static PRINCIPAL_ATTRIBUTES = [
    {
      friendlyName: "personalIdentityNumber", name: "urn:oid:1.2.752.29.4.13",
      info: "Enter personal identity number (12 digits, no hyphen)"
    },
    { friendlyName: "prid", name: "urn:oid:1.2.752.201.3.4", info: "Enter provisional ID" },
    { friendlyName: "eidasPersonIdentifier", name: "urn:oid:1.2.752.201.3.7", info: "Enter eIDAS person identifier" },
    {
      friendlyName: "mappedPersonalIdentityNumber", name: "urn:oid:1.2.752.201.3.16",
      info: "Enter personal identity number (12 digits, no hyphen)"
    },
    { friendlyName: "c - country", name: "urn:oid:2.5.4.6", info: "Enter country code (2 letters)" },
    { friendlyName: "dateOfBirth", name: "urn:oid:1.3.6.1.5.5.7.9.1", info: "Enter date of birth (YYYY-MM-DD)" },
    { friendlyName: "sn - surname", name: "urn:oid:2.5.4.4", info: "Enter surname" },
    { friendlyName: "givenName", name: "urn:oid:2.5.4.42", info: "Enter given name" }
  ];

  /**
   * Initializes the Requested Principal Selection extension element.
   */
  initRequestedPrincipalSelection() {
    let pseCheckbox = $('#saml-request-pse-present');
    let pseDiv = $('#saml-request-pse-div');

    let pseAttrsButtonDiv = $('#saml-request-pse-drop-div');
    let pseAttrsListingDiv = $('#saml-request-pse-attrs');
    let pseAttrsListingEntireDiv = $('#saml-request-pse-attrs-div');

    pseDiv.hide();

    pseAttrsButtonDiv.empty();
    for (let attr of AuthnRequest.PRINCIPAL_ATTRIBUTES) {
      pseAttrsButtonDiv.append($('<a>', {
        href: '#',
        class: 'dropdown-item',
        'data-pse-attr': attr.name,
        text: attr.name + ' (' + attr.friendlyName + ')',
        click: function(event) {
          event.preventDefault();

          let ad = $('<div>');
          if (pseAttrsListingDiv.children().length > 0) {
            ad.addClass("mt-4");
          }
          const inputId = generateRandomId();
          const buttonId = generateRandomId();
          ad.append($('<label>', {
            for: inputId,
            text: attr.friendlyName + ' (' + attr.name + ')'
          }));

          let inputDiv = $('<div>', {
            class: 'input-group mt-2'
          });
          inputDiv.append($('<input>', {
            id: inputId,
            type: 'text',
            'data-attrname': attr.name,
            placeholder: attr.info,
            class: 'form-control',
            'aria-describedby': buttonId
          }))
              .append($('<div>', { class: 'd-flex align-items-center position-absolute top-0 end-0 h-100 pe-3' })
                  .append($('<button>', {
                    id: buttonId,
                    type: 'button',
                    class: 'btn btn-close'
                  })));
          ad.append(inputDiv);
          pseAttrsListingDiv.append(ad);

          pseAttrsListingEntireDiv.show();
        }
      }));
    }

    pseAttrsListingEntireDiv.hide();
    pseAttrsListingDiv.empty();
    pseCheckbox.prop('checked', false);

    pseCheckbox.change(function() {
      pseDiv.toggle(this.checked);
    })

    pseAttrsListingDiv.on('click', 'button.btn-close', function() {
      $(this).parent().parent().parent().remove();

      if (pseAttrsListingDiv.children().length === 0) {
        pseAttrsListingEntireDiv.hide();
      }
    });
  }

  /**
   * Gets the Requested Principal Selection extension element.
   * @returns {null|*[]} a list of attributes or null
   */
  getRequestedPrincipalSelection() {
    if ($('#saml-request-pse-present').prop('checked')) {
      let attrs = [];
      let inputElements = $('#saml-request-pse-attrs input');

      $.each(inputElements, function() {
        let obj = {};
        obj.name = $(this).data('attrname');
        obj.value = $(this).val().trim() ? $(this).val().trim() : null;
        attrs.push(obj);
      });
      return attrs;
    }
    else {
      return null;
    }
  }

  static UM_MIME_TYPES = [ "text/plain", "text/markdown", "text/dummy" ];

  static UM_POSSIBLE_LANGUAGES = [
    { code: "sv", text: "Swedish" },
    { code: "en", text: "English" },
    { code: "de", text: "German" },
    { code: "fr", text: "French" },
    { code: "it", text: "Italian" },
    { code: "es", text: "Spanish" },
    { code: "xx", text: "Dummy - for error testing" },
    { code: null, text: "No language code added (error case)" }
  ];

  initUserMessage(um) {
    let umCheckbox = $('#saml-request-um-present');
    let umDiv = $('#saml-request-um-div');

    umDiv.hide();
    umCheckbox.prop('checked', um != null);

    let umMimeSelect = $('#saml-request-um-mimetype-select');
    umMimeSelect.empty();
    for (let mt of AuthnRequest.UM_MIME_TYPES) {
      umMimeSelect.append(new Option(mt, mt));
    }
    umMimeSelect.append(new Option("-- Not specified --", "exclude"));
    if (um) {
      umMimeSelect.val(um.mime_type || 'exclude');
    }

    let umMessagesDiv = $('#saml-request-um-messages-div');
    umMessagesDiv.empty();
    if (um && um.messages) {
      for (let msg of um.messages) {
        let msgDiv = this.createUserMessageDiv(msg);
        if (msgDiv) {
          umMessagesDiv.append(msgDiv);
        }
      }
    }

    let umAddMessageDiv = $('#saml-request-um-add-drop-div');
    umAddMessageDiv.empty();
    let thisObj = this;

    for (let lang of AuthnRequest.UM_POSSIBLE_LANGUAGES) {
      umAddMessageDiv.append($('<a>', {
        href: 'javascript:void(0)',
        class: 'dropdown-item',
        text: lang.code ? (lang.text + ' (' + lang.code + ')') : lang.text,
        click: function(event) {
          event.preventDefault();

          let obj = {
            lang_code: lang.code,
            language: lang.text,
            message: ''
          };
          let msgDiv = thisObj.createUserMessageDiv(obj);
          if (msgDiv) {
            umMessagesDiv.append(msgDiv);
          }
        }
      }));
    }

    if (um) {
      umDiv.show();
    }

    umCheckbox.change(function() {
      umDiv.toggle(this.checked);
    });
  }

  createUserMessageDiv(msg) {
    let msgId = generateRandomId();

    let msgDiv = $('<div>', {
      class: 'row mt-4'
    });

    let msgLabel = $('<label>', {
      class: 'col-sm-2',
      'data-langcode': msg.lang_code,
      for: msgId
    });
    if (msg.lang_code) {
      msgLabel.text(msg.language + ' (' + msg.lang_code + ')');
    }
    else {
      msgLabel.text("No language code added (error case)");
    }
    msgDiv.append(msgLabel);

    let textAreaDiv = $('<div>', {
      class: 'col-sm-10 d-flex',
    }).css({ "position": "relative" });

    let textArea = $('<textarea>', {
      class: 'form-control user-message flex-grow-1',
      id: msgId,
      rows: '3',
      text: msg.message || ''
    });
    textAreaDiv.append(textArea);

    let textAreaCloseButton = $('<button>', {
      type: 'button',
      class: 'btn-close align-self-start p-2',
      click: function() {
        msgDiv.remove();
      }
    }).css({
      "position": "absolute",
      "top": "0",
      "right": "14px"
    });
    textAreaDiv.append(textAreaCloseButton);

    msgDiv.append(textAreaDiv);

    return msgDiv;
  }

  getUserMessage() {
    if ($('#saml-request-um-present').prop('checked')) {
      let messages = [];
      $('#saml-request-um-messages-div .row').each(function() {
        let obj = {
          lang_code: $(this).find('label').data('langcode'),
          message: $(this).find('textarea').val()
        };
        messages.push(obj);
      });
      let mimeType = $("#saml-request-um-mimetype-select").val();
      if (mimeType === 'exclude') {
        mimeType = null;
      }
      return {
        mime_type: mimeType,
        messages: messages
      };
    }
    else {
      return null;
    }
  }

  initScoping() {
    let scopingCheckbox = $('#saml-request-scoping-present');
    let scopingDiv = $('#saml-request-scoping-div');

    scopingDiv.hide();
    scopingCheckbox.prop('checked', false);

    let scopingRequestIdsList = $('#saml-request-scoping-rid-div');
    $('#saml-request-scoping-rid-add-button').click(function() {
      let mainDiv = $('<div>', {
        class: 'row mt-3'
      });
      mainDiv.append($('<div>', {
        class: 'col-sm-2'
      }));
      mainDiv.append($('<div>', {
        class: 'col-sm-10'
      }).append($('<input>', {
        type: 'text',
        class: 'form-control',
        placeholder: 'Add Requester ID ...'
      })));

      scopingRequestIdsList.append(mainDiv);
    });

    let scopingIdpList = $('#saml-request-scoping-idps-div');
    $('#saml-request-scoping-add-button').click(function() {
      let mainDiv = $('<div>', {
        class: 'row mt-3'
      });
      mainDiv.append($('<div>', {
        class: 'col-sm-2'
      }));
      mainDiv.append($('<div>', {
        class: 'col-sm-10'
      }).append($('<input>', {
        type: 'text',
        class: 'form-control',
        placeholder: 'Add IdP/method identifier ...'
      })));

      scopingIdpList.append(mainDiv);
    });

    scopingCheckbox.change(function() {
      scopingDiv.toggle(this.checked);
    });
  }

  getScoping() {
    if ($('#saml-request-scoping-present').prop('checked')) {
      let scoping = {};
      scoping.requester_ids = [];
      scoping.idp_list = [];

      $('#saml-request-scoping-rid-div input').each(function() {
        let value = AuthnRequest.getValueFromInput($(this));
        if (value) {
          scoping.requester_ids.push(value);
        }
      });
      if (scoping.requester_ids.length === 0) {
        scoping.requester_ids = null;
      }

      $('#saml-request-scoping-idps-div input').each(function() {
        let value = AuthnRequest.getValueFromInput($(this));
        if (value) {
          scoping.idp_list.push(value);
        }
      });
      if (scoping.idp_list.length === 0) {
        scoping.idp_list = null;
      }

      return scoping;
    }
    else {
      return null;
    }
  }

  static SM_MIME_TYPES = [ "text", "text/plain", "text/markdown", "text/dummy" ];

  initSignMessage(idp, sm) {

    let smCheckbox = $('#saml-request-sm-present');
    let smDiv = $('#saml-request-sm-div');
    let smMimeSelect = $('#saml-request-sm-mimetype-select');

    for (let mt of AuthnRequest.SM_MIME_TYPES) {
      smMimeSelect.append(new Option(mt, mt));
    }
    smMimeSelect.append(new Option("-- Not specified --", "exclude"));

    if (sm) {
      smCheckbox.prop('checked', true);
      let smTextarea = $('#saml-request-sm-textarea');

      if (sm.message) {
        smTextarea.val(sm.message);
      }
      $('#saml-request-sm-encrypt-cb').prop('checked', sm.encrypt);

      $('#saml-request-sm-display-entity').val(sm.display_entity);
      smMimeSelect.val(sm.mime_type || 'exclude');
      AuthnRequest.setRadioButtonTrueFalseExclude('saml-request-sm-must-show', sm.must_show);
      smDiv.show();
    }
    else {
      smCheckbox.prop('checked', false);
      AuthnRequest.setRadioButtonTrueFalseExclude('saml-request-sm-must-show', true);
      $('#saml-request-sm-display-entity').val(idp);
      smDiv.hide();
    }

    smCheckbox.change(function() {
      smDiv.toggle(this.checked);
    });

  }

  getSignMessage() {
    if ($('#saml-request-sm-present').prop('checked')) {
      let sm = {};
      sm.message = $('#saml-request-sm-textarea').val();
      sm.mime_type = $("#saml-request-sm-mimetype-select").val();
      if (sm.mime_type === 'exclude') {
        sm.mime_type = null;
      }
      sm.encrypt = $('#saml-request-sm-encrypt-cb').is(':checked');
      sm.display_entity = AuthnRequest.getValueFromInput($('#saml-request-sm-display-entity'));
      sm.must_show = AuthnRequest.getRadioButtonTrueFalseExclude('saml-request-sm-must-show');
      return sm;
    }
    else {
      return null;
    }
  }

}
