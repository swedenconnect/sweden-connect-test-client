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
 * State class for OIDC.
 */
class OidcState extends State {

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
     * Returns the currently selected RP.
     *
     * @returns {string|null} The currently selected RP or null
     */
    getSelectedRp() {
        return this.get('selectedRp');
    }

    /**
     * Assigns the selected RP
     * @param rp the RP that was selected
     */
    setSelectedRp(rp) {
        this.set('selectedRp', rp, true);
    }

    /**
     * Returns the currently selected OP.
     * @returns {string|null} The currently selected OP or null
     */
    getSelectedOp() {
        return this.get('selectedOp');
    }

    /**
     * Assigns the selected OP.
     * @param op the OP that was selected
     */
    setSelectedOp(op) {
        this.set('selectedOp', op, true);
    }

    /**
     * Returns the setup data (see SetupAuthentication).
     * @returns {OIDCSetupAuthentication|null} the setup data.
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
     * @param authnRequest the authentication request XML/JSON
     * @param relayState the relay state
     * @param parameters the parameters (from the AuthnRequest view)
     */
    setActiveAuthnRequest(authnRequest, relayState, parameters) {
        this.set('authn_request_data', {authn_request: authnRequest, relay_state: relayState, parameters: parameters});
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

const OIDC_STATE = new OidcState('sctc.oidc', 'sctc.oidc.session');

/**
 * Main class for OIDC authentication.
 */
class OIDCAuthentication {

    static OIDC_STATE_SETUP = 'setup';
    static OIDC_STATE_BUILD = 'build';
    static OIDC_STATE_AUTHN = 'authn';
    static OIDC_STATE_RESULT = 'result';

    /**
     * Sets up the OIDC authentication view. The view is either loaded "fresh", or continues from a saved session state.
     */
    constructor() {
        this.setupAuthn = new OIDCSetupAuthentication(
            () => {
                this.onSetupPhaseNext();
            },
            () => {
                let importString = $('#oidc-import-input').prop("value");
                this.onSetupPhaseNext(importString);
            }
        );
        this.authnRequestView = null;
        this.resultView = null;

        this.setupAuthn.init();
        this.setupAuthn.displaySetup();

        const state = this.getSessionState();

        if (state === OIDCAuthentication.OIDC_STATE_SETUP) {
            OIDCAuthnRequest.hide();
            OIDCAuthenticationResult.hide();
            return;
        }
        else {
            // If we are not in our initial state, we disable the view, i.e., we display it, but stick to the selected values.
            this.setupAuthn.disableSetup();
        }

        // We are in "build authentication request state" ...
        if (state === OIDCAuthentication.OIDC_STATE_BUILD) {
            this.activateAuthnRequestView();
            OIDCAuthenticationResult.hide();
            return;
        }

        // We are in authn or result "mode" ...
        const authnRequestData = OIDC_STATE.getActiveAuthnRequest();
        if (!authnRequestData) {
            // No session. Reset
            this.onRestart();
            return;
        }
        this.resultView = new OIDCAuthenticationResult(authnRequestData, () => this.onRestart());

        if (state === OIDCAuthentication.OIDC_STATE_AUTHN) {

            // Handle that we did not get oidc_responseData ...
            if (!window.oidc_responseData) {
                this.onRestart();
                return;
            }
            this.updateSessionState(OIDCAuthentication.OIDC_STATE_RESULT);
            this.resultView.verifyResponse(window.oidc_responseData);

        }
        else { // OidcAuthentication.OIDC_STATE_RESULT
            const resultData = OIDC_STATE.getAuthnResult();
            if (!resultData) {
                this.onRestart();
                return;
            }
            this.resultView.displayResult(resultData);
            OIDCAuthenticationResult.scrollTo();
        }
    }

    /**
     * Scrolls to the active view. Called when selecting "OIDC" in the main menu.
     */
    scrollToActiveView() {
        const state = this.getSessionState();
        if (state === OIDCAuthentication.OIDC_STATE_BUILD) {
            OIDCAuthnRequest.scrollTo();
        }
        else if (state === OIDCAuthentication.OIDC_STATE_RESULT) {
            OIDCAuthenticationResult.scrollTo();
        }
    }

    /**
     * Sets up the "build authentication view".
     */
    activateAuthnRequestView(importString = null) {
        $.ajax({
                   url: buildUrl('/oidc/authn/template'),
                   type: 'GET',
                   data: {
                       rp: OIDC_STATE.getSelectedRp(),
                       op: OIDC_STATE.getSelectedOp()
                   },
                   success: (template) => {
                       this.authnRequestView = new OIDCAuthnRequest(
                           template,
                           () => this.onRestart(),
                           (pars) => this.onSendAuthnRequest(pars)
                       );
                       if (importString) {
                           try {
                               this.authnRequestView.import(importString);
                           }
                           catch (error) {
                               console.log("Failed to import request");
                               console.error(error);
                           }
                       }
                       this.authnRequestView.init();
                       OIDCAuthnRequest.scrollTo();
                   },
                   error: (error) => {
                       console.error("Failed to generate authentication request template: " + JSON.stringify(error));
                   }
               });
    }

    /**
     * Is called when the Next-button is clicked in the setup-view.
     */
    onSetupPhaseNext(importString = null) {
        this.setupAuthn.disableSetup();
        this.updateSessionState(OIDCAuthentication.OIDC_STATE_BUILD);
        this.activateAuthnRequestView(importString);
    }

    /**
     * Is called when the authentication flow is restarted.
     */
    onRestart() {
        OIDCAuthnRequest.hide();
        this.authnRequestView = null;

        OIDCAuthenticationResult.hide();
        this.resultView = null;

        this.updateSessionState(OIDCAuthentication.OIDC_STATE_SETUP);
        this.setupAuthn.displaySetup();

        let mainDiv = $('#main-oidc');
        let pos = mainDiv.offset().top;
        $('html, body').animate({scrollTop: pos}, 'slow');
    }

    /**
     * Callback function that is invoked to generate an AuthnRequest and redirect the browser.
     * @param authnRequest the AuthnRequest parameters
     */
    onSendAuthnRequest(authnRequest) {
        $.ajax({
                   url: buildUrl('/oidc/authn/generate'),
                   type: 'POST',
                   contentType: 'application/json',
                   data: JSON.stringify(this.authnRequestView.getAuthnRequestParameters()),
                   dataType: 'json',
                   success: (response) => {
                       this.updateSessionState(OIDCAuthentication.OIDC_STATE_AUTHN);

                       const authnRequestPars = this.authnRequestView.getAuthnRequestParameters();
                       authnRequestPars.id = response.id;
                       authnRequestPars.issue_instant = response.issue_instant;

                       OIDC_STATE.setActiveAuthnRequest(
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
                       console.error("Failed to generate OIDC AuthnRequest: " + JSON.stringify(error));
                   }

               });
    }

    /**
     * Gets the current session state. It can be 'setup', 'build', 'authn' and 'result'.
     * @returns {string} the state
     */
    getSessionState() {
        let state = OIDC_STATE.get('state');
        if (!state) {
            OIDC_STATE.set('state', OIDCAuthentication.OIDC_STATE_SETUP);
            return OIDCAuthentication.OIDC_STATE_SETUP;
        }
        return state;
    }

    /**
     * Updates the OIDC session state.
     * @param state the new state
     */
    updateSessionState(state) {
        OIDC_STATE.set('state', state, false, true);
    }

}

class OIDCAuthenticationResult {

    constructor(authnRequestData, onRestartCallback) {
        this.restartCallback = onRestartCallback;
        this.authnRequestData = authnRequestData;

        $('#oidc-authn-result-restart-button').click(() => {
            $("#oidc-request-main").show();
            this.restartCallback();
        });
    }

    static hide() {
        $('#oidc-authn-result').hide();
    }

    static scrollTo() {
        let resultDiv = $('#oidc-authn-result');
        resultDiv.show();
        let pos = resultDiv.offset().top - 38;
        $('html, body').animate({scrollTop: pos}, 'slow');
    }

    verifyResponse(responseData) {

        const verifyInput = {
            rp: OIDC_STATE.getSelectedRp(),
            authn_request: this.authnRequestData.authn_request,
            sent_relay_state: this.authnRequestData.relay_state,
            response_data: responseData
        };

        $.ajax({
                   url: buildUrl('/oidc/authn/verify'),
                   type: 'POST',
                   contentType: 'application/json',
                   data: JSON.stringify(verifyInput),
                   dataType: 'json',
                   success: (result) => {
                       OIDC_STATE.setAuthnResult(result);
                       this.displayResult(result);
                       OIDCAuthenticationResult.scrollTo();
                   },
                   error: (error) => {
                       console.error("Failed to process OIDC response: " + JSON.stringify(error));
                       const result = {
                           errors: ["Error while processing OIDC response"]
                       };
                       OIDC_STATE.setAuthnResult(result);
                       this.displayResult(result);
                   }
               });
    }

    displayResult(resultData) {
        $("#oidc-request-main").hide();
        const resultErrorDiv = $('#oidc-authn-result-op-error');
        resultErrorDiv.removeClass('bg-secondary bg-warning bg-danger');

        $('#oidc-authn-result-view-authnrequest').click(() => {
            codeViewer.displayURL('Authentication Request', resultData.authorizationRequest);
        });

        if (resultData.errors && resultData.errors.length > 0) {
            const heading = resultErrorDiv.find('.card-header');
            if (resultData.op_error) {
                heading.text("OP Error Status");
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

        const viewResponseButton = $('#oidc-authn-result-view-response');
        if (resultData.response) {
            viewResponseButton.click(() => {
                codeViewer.displayJson('OIDC Response', resultData.response);
            });
        }
        else {
            viewResponseButton.hide();
        }

        $('#oidc-authn-result-view-authnrequest-details').click((event) => {
            $(event.target).hide();
            if (resultData.requestParameters) {
                this.displayAuthnRequestDetails(resultData.requestParameters);
                $('#oidc-authn-result-authnrequest-details').show();
            }
        });

        const responseDiv = $('#oidc-authn-result-response');
        const accessTokenDiv = $('#oidc-authn-result-access-token');
        const idTokenDiv = $('#oidc-authn-result-id-token');
        const userInfoDiv = $('#oidc-authn-result-userinfo');
        if (resultData.responseParameters) {
            const tableDiv = responseDiv.find('tbody');

            for (var prop in resultData.responseParameters) {
                if (Object.prototype.hasOwnProperty.call(resultData.responseParameters, prop)) {
                    let value = resultData.responseParameters[prop];
                    if (!prop.includes("_token")) {
                        tableDiv.append(this.createRow(prop, value));
                    }
                }
            }
            responseDiv.show();
            const accessTokenTableDiv = accessTokenDiv.find('tbody');
            for (var prop in resultData.accessTokenClaims) {
                if (Object.prototype.hasOwnProperty.call(resultData.accessTokenClaims, prop)) {
                    accessTokenTableDiv.append(this.createRow(prop, resultData.accessTokenClaims[prop]));
                }
            }
            accessTokenDiv.show();
            const idTokenTableDiv = idTokenDiv.find('tbody');
            for (var prop in resultData.idTokenClaims) {
                if (Object.prototype.hasOwnProperty.call(resultData.idTokenClaims, prop)) {
                    idTokenTableDiv.append(this.createRow(prop, resultData.idTokenClaims[prop]));
                }
            }
            for (var prop in resultData.missingIdTokenClaims) {
                if (Object.prototype.hasOwnProperty.call(resultData.missingIdTokenClaims, prop)) {
                    idTokenTableDiv.append(this.createRow(prop, "Requested value " + prop + " was missing in ID token.",
                                                          'table-text table-danger',
                                                          'table-text table-danger'));
                }
            }
            idTokenDiv.show();
            const userInfoTableDiv = userInfoDiv.find('tbody');
            for (var prop in resultData.userInfoClaims) {
                if (Object.prototype.hasOwnProperty.call(resultData.userInfoClaims, prop)) {
                    userInfoTableDiv.append(this.createRow(prop, resultData.userInfoClaims[prop])
                    );
                }
            }
            for (var prop in resultData.missingUserInfoClaims) {
                if (Object.prototype.hasOwnProperty.call(resultData.missingUserInfoClaims, prop)) {
                    userInfoTableDiv.append(this.createRow(prop, "Requested value " + prop + " was missing in" +
                        " Userinfo.",
                                                           'table-text table-danger',
                                                           'table-text table-danger'));
                }
            }
            userInfoDiv.show();
        }
        else {
            responseDiv.hide();
        }

        const viewAssertionButton = $('#oidc-authn-result-view-assertion');
        if (resultData.assertion) {
            viewAssertionButton.click(() => {
                codeViewer.displayXml('Assertion', resultData.assertion);
            });
        }
        else {
            viewAssertionButton.hide();
        }

        const assertionDiv = $('#oidc-authn-result-assertion');
        if (resultData.assertion_details) {
            const tableDiv = $('#body-assertion');

            tableDiv.append(this.createRow("ID", resultData.assertion_details.id));
            tableDiv.append(this.createRow("Issue Instant", resultData.assertion_details.issue_instant));
            tableDiv.append(this.createRow("Is Signed?", resultData.assertion_details.signed ? 'Yes' : 'No'));
            tableDiv.append(this.createRow("Issuer", resultData.assertion_details.issuer));
            const subjectNameID = resultData.assertion_details.subject && resultData.assertion_details.subject.name_id;
            tableDiv.append(this.createRow("Subject | NameID", subjectNameID
                ? [[subjectNameID.value || "Name not assigned"],
                    ["Format", subjectNameID.format],
                    ["Name qualifier", subjectNameID.name_qualifier],
                    ["RP name qualifier", subjectNameID.rp_name_qualifier],]
                : null));
            const confirmation = resultData.assertion_details.subject && resultData.assertion_details.subject.confirmation;
            tableDiv.append(this.createRow("Subject | Confirmation", confirmation
                ? [["Method", confirmation.method],
                    ["Address", confirmation.address],
                    ["In response to", confirmation.in_response_to],
                    ["Not before", confirmation.not_before],
                    ["Not on or after", confirmation.not_after],
                    ["Recipient", confirmation.recipient]]
                : null));
            const conditions = resultData.assertion_details.conditions;
            tableDiv.append(this.createRow("Conditions", conditions
                ? [["Not before", conditions.not_before],
                    ["Not on or after", conditions.not_after],
                    ["Audience restriction(s)", conditions.audiences ? conditions.audiences.join(', ') : null]]
                : null));
            const authnStatement = resultData.assertion_details.authentication_statement;
            tableDiv.append(this.createRow("Authentication Statement", authnStatement
                ? [["Authentication instant", authnStatement.authn_instant],
                    ["Subject locality", authnStatement.subject_locality],
                    ["Authentication Context Class Ref", authnStatement.authn_context_class_ref]]
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
     * @param parameters the request parameters
     */
    displayAuthnRequestDetails(parameters) {
        const detailsDiv = $('#oidc-authn-result-authnrequest-details');
        const detailsTable = detailsDiv.find('tbody');
        for (var prop in parameters) {
            if (Object.prototype.hasOwnProperty.call(parameters, prop)) {
                let value = parameters[prop];
                if (prop.includes("_token")) {
                    value.replace('/\./g', '$&\n');
                }
                detailsTable.append(this.createRow(prop, value));
            }
        }

        detailsDiv.show();
    }

    createRow(title, contents, thClass = 'table-text', tdClass = 'table-text') {

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
                class: thClass,
                text: title
            }))
            .append($('<td>', {
                class: tdClass,
                html: html || "Not assigned"
            }));
    }

}

/**
 * Class that handles the setup-phase.
 */
class OIDCSetupAuthentication {

    /**
     * Constructor.
     */
    constructor(onNextCallback, onImportCallback) {
        this.nextCallback = onNextCallback;
        this.importCallback = onImportCallback
        this.oidcInfoCache = OIDC_STATE.getSetupData() || null;
    }

    /**
     * Initializes the setup section.
     */
    init() {

        const self = this;

        $('#oidc-rp-select').change(function () {
            let selectedRp = $(this).val() === 'none' ? null : $(this).val();
            OIDC_STATE.setSelectedRp(selectedRp);
            self.displaySelectedRp(selectedRp);
        });

        $('#oidc-view-metadata').click(function () {
            let entityId = $(this).val();
            $.ajax({
                       url: buildUrl('/oidc/rp/metadata'),
                       type: 'GET',
                       data: {
                           rp: entityId
                       },
                       success: (metadata) => {
                           const sortedMetadata = Object.fromEntries(
                               Object.entries(metadata).sort(([keyA], [keyB]) =>
                                                                 keyA.localeCompare(keyB)
                               )
                           );
                           codeViewer.displayJson(entityId, sortedMetadata);
                       },
                       error: (error) => {
                           console.error("Failed to get RP metadata: " + JSON.stringify(error));
                       }
                   });
        });

        $('#oidc-op-select').change(function () {
            let selectedOp = $(this).val() === 'none' ? null : $(this).val();
            OIDC_STATE.setSelectedOp(selectedOp);
            self.displaySelectedOp(selectedOp);
        });

        $('#oidc-op-view-metadata').click(function () {
            let entityId = OIDC_STATE.getSelectedOp();
            $.ajax({
                       url: buildUrl('/oidc/op/metadata'),
                       type: 'GET',
                       data: {
                           op: entityId
                       },
                       success: (metadata) => {
                           codeViewer.displayJson(entityId, metadata);
                       },
                       error: (error) => {
                           console.error("Failed to get OP metadata: " + JSON.stringify(error));
                       }
                   });
        });

        $('#oidc-authn-next-button').click(function () {
            self.nextCallback();
        });

        $('#oidc-authn-import-button').click(function () {
            self.importCallback();
        });

    }

    /**
     * Displays the setup view where the user selects RP and OP for authentication.
     */
    displaySetup() {

        /*if (this.oidcInfoCache) {
            this.displayRps(this.oidcInfoCache.rps);
            this.displayOps(this.oidcInfoCache.ops);
        }
        else {*/

        $.ajax({
                   url: buildUrl('/oidc/authn/info'),
                   type: 'GET',
                   success: (info) => {
                       this.oidcInfoCache = info;
                       OIDC_STATE.setSetupData(this.oidcInfoCache);
                       this.displayRps(this.oidcInfoCache.rps);
                       this.displayOps(this.oidcInfoCache.ops);
                   },
                   error: (error) => {
                       console.error("Failed to get RP and OP info: " + JSON.stringify(error));
                       this.displayRps([]);
                       this.displayOps([]);
                   }
               });
        //}
        $('#oidc-authn-next-button-div').show();
    }

    /**
     * Disables the setup view.
     */
    disableSetup() {
        $('#oidc-rp-select').prop('disabled', true);
        $('#oidc-op-select').prop('disabled', true);
        $('#oidc-authn-next-button').prop('disabled', true);
        $('#oidc-authn-next-button-div').hide();
    }

    /**
     * Displays the different RP:s that are available
     * @param rpInfo a list of RP info
     */
    displayRps(rpInfo) {
        let rpSelect = $('#oidc-rp-select');
        rpSelect.prop('disabled', false);
        if (rpSelect.find('option').length === 0) {
            $('#rp-info').hide();
            rpSelect.append(new Option("--- Select RP ---", "none", true, false));
            for (const rp of rpInfo) {
                rpSelect.append(new Option(rp.entity_id, rp.entity_id, false, false));
            }
        }
        let selectedRp = OIDC_STATE.getSelectedRp();
        if (selectedRp) {
            rpSelect.val(selectedRp);
            this.displaySelectedRp(selectedRp);
        }
    }

    /**
     * Displays info about the selected RP.
     * @param entityId the RP entity ID or "none"/null
     */
    displaySelectedRp(entityId) {
        if (!entityId || entityId === "none") {
            $('#rp-info').hide();
            $('#oidc-authn-next-button').prop('disabled', true);
        }
        else {
            for (const rp of this.oidcInfoCache.rps) {
                if (rp.entity_id === entityId) {
                    $('#rp-description').text(rp.description);
                    let rpUrl = $('#oidc-metadata-url');
                    rpUrl.attr('href', rp.metadata_url);
                    rpUrl.text(rp.metadata_url);
                    $('#oidc-view-metadata').attr('value', rp.entity_id);
                    $('#rp-info').show();

                    if (OIDC_STATE.getSelectedOp()) {
                        $('#oidc-authn-next-button').prop('disabled', false);
                    }
                    break;
                }
            }
        }
    }

    /**
     * Displays the OP:s that are available.
     * @param opInfo a list of OP info
     */
    displayOps(opInfo) {
        let opSelect = $('#oidc-op-select');
        opSelect.prop('disabled', false);
        if (opSelect.find('option').length === 0) {
            $('#op-info').hide();
            opSelect.append(new Option("--- Select OP ---", "none", true, false));
            for (const op of opInfo) {
                opSelect.append(new Option(op.entity_id, op.entity_id, false, false));
            }
        }
        let selectedOp = OIDC_STATE.getSelectedOp();
        if (selectedOp) {
            opSelect.val(selectedOp);
            this.displaySelectedOp(selectedOp);
        }
    }

    /**
     * Displays info about the selected OP.
     * @param entityId the OP entity ID or "none"/null
     */
    displaySelectedOp(entityId) {
        if (!entityId || entityId === "none") {
            $('#op-info').hide();
            $('#oidc-authn-next-button').prop('disabled', true);
        }
        else {
            for (const op of this.oidcInfoCache.ops) {
                if (op.entity_id === entityId) {
                    $('#op-displayname').text(op.display_name);
                    $('#op-description').text(op.description);
                    $('#op-view-metadata').attr('value', op.entity_id);
                    $('#op-info').show();

                    if (OIDC_STATE.getSelectedRp()) {
                        $('#oidc-authn-next-button').prop('disabled', false);
                    }

                    break;
                }
            }
        }
    }
}

/**
 * Represents the OIDC AuthnRequest regarding the HTML elements that are displayed.
 */
class OIDCAuthnRequest {

    /**
     * Constructor that initializes all elements for the OIDC AuthnRequest.
     * @param template the AuthnRequest template
     * @param onRestartCallback callback to invoke when flow is restarted
     * @param onSendAuthnRequestCallback callback to invoked when "Send request" is clicked
     */
    constructor(template, onRestartCallback, onSendAuthnRequestCallback) {
        this.pars = template;
        this.restartCallback = onRestartCallback;
        this.sendAuthnRequestCallback = onSendAuthnRequestCallback;
    }

    export() {
        codeViewer.displayJson("Export", btoa(JSON.stringify(this.pars)));
    }

    import(base64String) {
        this.pars = JSON.parse(atob(base64String));
    }

    /**
     * Initializes the AuthnRequest builder view.
     */
    init() {
        this.initRequestObjectOptions();
        this.initAdvancedOptions();
        this.initKeyOptions();
        let parent = this;
        // advanced options toggle
        let advancedOptions = $('#oidc-advanced-authn-options');
        advancedOptions.click(function () {
            if (advancedOptions.prop("checked")) {
                $('#oidc-advanced-authn-request').show();

            }
            else {
                $('#oidc-advanced-authn-request').hide();
            }
        });
        let keyOptions = $('#oidc-advanced-keys-request-check');
        keyOptions.click(function () {
            if (keyOptions.prop("checked")) {
                $('#oidc-advanced-keys-request').show();
            }
            else {
                $('#oidc-advanced-keys-request').hide();
            }
        });
        $('#oidc-request-claims-id-remove-button')
            .off()
            .on("click", function () {
                let lastElement = $('#oidc-id-claims-table').children().last()[0];
                if (!lastElement.id.includes('template')) {
                    lastElement.remove();
                    parent.computeClaims();
                }
            });
        $('#oidc-request-claims-present').click(function () {
            parent.computeClaims();
        });
        $('#oidc-request-claims-request-body').click(function () {
            parent.computeClaims();
        });
        this.claimIdentifiers = {
            "id": {
                "table": "oidc-id-claims-table",
                "row": "id-claims-row-template",
                "value-checkbox": "id-claims-template-with-value",
                "essential-checkbox": "id-claims-template-essential",
                "value-input": "id-claims-template-value",
                "key-input": "id-claims-template-key",
                "value-column": "id-claims-template-value-column",
                "id-token-checkbox": "id-claims-template-id-token",
                "userinfo-checkbox": "id-claims-template-userinfo"
            }
        }
        let addClaimFunction = function (type, currentIndex) {
            let rowTemplate = parent.getClaimElement('template', parent.claimIdentifiers["id"]["row"]);
            let clone = rowTemplate.clone(true, true);
            // Find all elements with IDs in the clone
            clone.attr('id', parent.claimIdentifiers["id"]["row"].replace("template", currentIndex));
            clone.find('[id]').each(function () {
                let oldId = $(this).attr('id');
                let newId = oldId.replace('template', currentIndex);
                $(this).attr('id', newId);
            });
            clone.removeAttr("hidden");
            clone.removeClass("template");

            $("#oidc-id-claims-table > div:last").after(clone);

            let valueCheckbox = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["value-checkbox"]);
            let keyInput = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["key-input"]);
            let valueInput = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["value-input"]);
            let essentialCheckBox = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["essential-checkbox"]);
            let idTokenCheckbox = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["id-token-checkbox"]);
            let userinfoCheckbox = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["userinfo-checkbox"]);
            idTokenCheckbox.click(function () {
                parent.computeClaims();
            })
            userinfoCheckbox.click(function () {
                parent.computeClaims();
            })
            let checkboxFunction = function () {
                let isChecked = valueCheckbox.prop("checked");
                let valueColumn = parent.getClaimElement(currentIndex, parent.claimIdentifiers[type]["value-column"]);
                valueColumn.prop('disabled', !isChecked);
                if (isChecked) {
                    essentialCheckBox.prop("checked", false);
                }
                else {
                    valueColumn.prop("value", '');
                }
                parent.computeClaims();
            };
            valueCheckbox.click(checkboxFunction);
            checkboxFunction();
            parent.computeClaims();
            essentialCheckBox.click(function () {
                valueCheckbox.prop("checked", false);
                checkboxFunction();
                parent.computeClaims();
            })
            keyInput.change(function () {
                parent.computeClaims();
            });
            valueInput.change(function () {
                parent.computeClaims();
            });
        };

        $('#oidc-request-claims-id-add-button')
            .off('click')
            .on('click', function () {
                addClaimFunction('id', $('#oidc-id-claims-table').children().length);
            });

        this.initField(
            '#oidc-request-scope-present',
            "#oidc-request-scope-request-body",
            '#oidc-request-scope-input',
            "scope"
        );

        this.initField(
            '#oidc-request-redirect-present',
            "#oidc-request-redirect-request-body",
            '#oidc-request-redirect-input',
            "redirectUri"
        );

        this.initField(
            '#oidc-request-client_id-present',
            "#oidc-request-client_id-request-body",
            '#oidc-request-client_id-input',
            "clientId"
        );

        this.initField(
            '#oidc-request-acr_values-present',
            "#oidc-request-acr_values-request-body",
            '#oidc-request-acr_values-input',
            'acrValues'
        );

        $("#oidc-request-claims-textarea").prop('disabled', true);


        $('#oidc-request-restart-button').click(() => {
            $("#oidc-request-main").show();
            $('#oidc-id-claims-table')
                .children()
                .not('[id*="template"]')
                .remove();
            $('#oidc-userinfo-claims-table')
                .children()
                .not('[id*="template"]')
                .remove();
            parent.computeClaims();
            $("#oidc-import-input").prop("value", "");
            this.restartCallback();
        });

        $('#oidc-request-submit-button').click(() => {
            this.sendAuthnRequestCallback(this.readAndGetAuthnRequestParameters());
        });

        $('#oidc-request-export-button').click(() => {
            this.export();
        });

        let umDiv = $('#oidc-request-um-div');

        let umAddMessageDiv = $('#oidc-request-um-add-drop-div');
        umAddMessageDiv.empty();
        let umMessagesDiv = $("#oidc-request-um-messages-div");
        let thisObj = this;

        for (let lang of AuthnRequest.UM_POSSIBLE_LANGUAGES) {
            umAddMessageDiv.append($('<a>', {
                href: 'javascript:void(0)',
                class: 'dropdown-item',
                text: lang.code ? (lang.text + ' (' + lang.code + ')') : lang.text,
                click: function (event) {
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


        let umCheckbox = $("#oidc-request-um-present");
        let um64 = $('#oidc-request-um-b64');
        um64.prop("checked", parent.pars["userMessage"]["b64Encode"]);
        um64.change(function () {
            parent.pars["userMessage"]["b64Encode"] = this.checked;
        })
        umCheckbox.change(function () {
            umDiv.toggle(this.checked);
            parent.pars["userMessage"]["valuePresent"] = this.checked;
        });
        let rbCheckbox = $('#oidc-request-um-request-body');
        rbCheckbox.change(function () {
            parent.pars["userMessage"]["requestBody"] = this.checked;
        });
        let umMimeType = $('#oidc-request-um-mimetype-select');
        umMimeType.change(function () {
            parent.pars["userMessage"]["mime_type"] = umMimeType.prop("value");
        });
        umCheckbox.change();
        umMimeType.change();

        let sigDiv = $('#oidc-request-sig-div');

        let sigAddMessageDiv = $('#oidc-request-sig-add-drop-div');
        sigAddMessageDiv.empty();

        let sigMessagesDiv = $('#oidc-request-sig-messages-div');

        for (let lang of AuthnRequest.UM_POSSIBLE_LANGUAGES) {
            sigAddMessageDiv.append($('<a>', {
                href: 'javascript:void(0)',
                class: 'dropdown-item',
                text: lang.code ? (lang.text + ' (' + lang.code + ')') : lang.text,
                click: function (event) {
                    event.preventDefault();

                    let obj = {
                        lang_code: lang.code,
                        language: lang.text,
                        message: ''
                    };
                    let msgDiv = thisObj.createUserMessageDiv(obj, true);
                    if (msgDiv) {
                        sigMessagesDiv.append(msgDiv);
                    }
                }
            }));
        }

        let sigCheckbox = $('#oidc-request-sig-present');
        let sigb64Checkbox = $('#oidc-request-sig-b64')
        let sigRbCheckbox = $('#oidc-request-sig-request-body');
        sigb64Checkbox.prop("checked", parent.pars["signMessage"]["b64Encode"]);
        sigb64Checkbox.change(function () {
            parent.pars["signMessage"]["b64Encode"] = this.checked;
        })
        sigCheckbox.change(function () {
            sigDiv.prop("hidden", !(this.checked || sigRbCheckbox.prop("checked")));
            parent.pars["signMessage"]["valuePresent"] = this.checked;
        });


        sigRbCheckbox.change(function () {
            sigDiv.prop("hidden", !(this.checked || sigCheckbox.prop("checked")));
            parent.pars["signMessage"]["requestBody"] = this.checked;
        });

        let sigMimeType = $('#oidc-request-sig-mimetype-select');
        sigMimeType.change(function () {
            parent.pars["signMessage"]["mime_type"] = sigMimeType.prop('value');
        });

        sigCheckbox.change();
        sigMimeType.change();
    }

    createUserMessageDiv(msg, sig = false) {

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
        }).css({"position": "relative"});

        let textArea = $('<textarea>', {
            class: 'form-control user-message flex-grow-1',
            id: msgId,
            rows: '3',
            text: msg.message || ''
        });
        textAreaDiv.append(textArea);
        let parent = this
        if (sig) {
            textArea.change(function () {
                parent.pars["signMessage"]["signMessage"]["message#" + msg.lang_code] = textArea.prop('value');
            });
        }
        else {
            textArea.change(function () {
                parent.pars.userMessage["message#" + msg.lang_code] = textArea.prop('value');
            });
        }
        let textAreaCloseButton = $('<button>', {
            type: 'button',
            class: 'btn-close align-self-start p-2',
            click: function () {
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

    getClaimElement(currentIndex, templateIdentifier) {
        return $('#' + templateIdentifier.replace("template", currentIndex));
    }

    computeClaims() {
        let outerClaims = {};
        let parent = this;

        function computeChild(child, claims) {
            if (child.attr("class").includes('claim-row') && !child.attr("class").includes('template')) {
                let split = child.attr("id").split("-");
                let index = parseInt(split[3], 10);
                let keyInput = parent.getClaimElement(index, parent.claimIdentifiers["id"]["key-input"]);
                let isEssential = parent.getClaimElement(index, parent.claimIdentifiers["id"]["essential-checkbox"]).prop("checked");
                let isValue = parent.getClaimElement(index, parent.claimIdentifiers["id"]["value-checkbox"]).prop("checked");
                let isIdTokenClaim = parent.getClaimElement(index, parent.claimIdentifiers["id"]["id-token-checkbox"]).prop("checked");
                let isUserInfoClaim = parent.getClaimElement(index, parent.claimIdentifiers["id"]["userinfo-checkbox"]).prop("checked");
                if (isIdTokenClaim) {
                    if (!claims["id_token"]) {
                        claims["id_token"] = {};
                    }
                    claims["id_token"][keyInput.val()] = {};
                    if (isEssential) {
                        claims["id_token"][keyInput.val()] = {"essential": true};
                    }
                    else if (isValue) {
                        let valueInput = parent.getClaimElement(index, parent.claimIdentifiers["id"]["value-input"]);
                        let value = valueInput.prop("value");
                        if (value.includes(",")) {
                            let values = value.split(",");
                            claims["id_token"][keyInput.val()] = {"values": values};
                        }
                        else {
                            claims["id_token"][keyInput.val()] = {"value": value};
                        }
                    }
                    else {
                        claims["id_token"][keyInput.val()] = null;
                    }
                }
                if (isUserInfoClaim) {
                    if (!claims["userinfo"]) {
                        claims["userinfo"] = {};
                    }
                    claims["userinfo"][keyInput.val()] = {};
                    if (isEssential) {
                        claims["userinfo"][keyInput.val()] = {"essential": true};
                    }
                    else if (isValue) {
                        let valueInput = parent.getClaimElement(index, parent.claimIdentifiers["id"]["value-input"]);
                        let value = valueInput.prop("value");
                        if (value.includes(",")) {
                            let values = value.split(",");
                            claims["userinfo"][keyInput.val()] = {"values": values};
                        }
                        else {
                            claims["userinfo"][keyInput.val()] = {"value": value};
                        }
                    }
                    else {
                        claims["userinfo"][keyInput.val()] = null;
                    }
                }
            }
        }

        $("#oidc-id-claims-table").children().each(function () {
            let child = $(this);
            computeChild(child, outerClaims);
        });
        let claimsTextArea = $("#oidc-request-claims-textarea");
        let json = JSON.stringify(outerClaims, null, 2);

        let inRequest = $("#oidc-request-claims-present").prop("checked");
        let inRequestBody = $("#oidc-request-claims-request-body").prop("checked");

        let disabled = !(inRequest || inRequestBody);
        if (!disabled) {
            claimsTextArea.prop("value", json);
            claimsTextArea.prop("placeholder", json);
            this.pars.claims = outerClaims;
        }
        else {
            claimsTextArea.prop("value", "{}");
            claimsTextArea.prop("placeholder", "No claims will be sent");
        }
    }

    initNestedField(
        presentElementId,
        requestBodyId,
        inputElementId,
        valueReference = null
    ) {
        let parent = this;
        let presentElement = $(presentElementId);
        let inputElement = $(inputElementId);
        let requestBodyElement = $(requestBodyId);
        inputElement.prop("value", parent.pars[valueReference[0]][valueReference[1]]["value"]);
        presentElement.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["valuePresent"]);
        requestBodyElement.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["requestBody"]);
        requestBodyElement.click(function () {
            let isChecked = presentElement.prop('checked');
            parent.pars[valueReference[0]][valueReference[1]]["requestBody"] = requestBodyElement.prop("checked");
            let isRbChecked = requestBodyElement.prop('checked');
            let disabled = !(isChecked || isRbChecked);
            inputElement.prop('disabled', disabled);
            if (disabled) {
                inputElement.prop('value', '');
            }
            else {
                inputElement.prop('value', parent.pars[valueReference[0]][valueReference[1]]["value"]);
            }
        });
        let onClickFunction = function () {
            let isChecked = presentElement.prop('checked');
            parent.pars[valueReference[0]][valueReference[1]]["valuePresent"] = isChecked;
            let isRbChecked = requestBodyElement.prop('checked');
            let disabled = !(isChecked || isRbChecked);
            inputElement.prop('disabled', disabled);
            if (disabled) {
                inputElement.prop('value', '');
            }
            else {
                inputElement.prop('value', parent.pars[valueReference[0]][valueReference[1]]["value"]);
            }
        };
        if (valueReference != null) {
            inputElement.change(function () {
                parent.pars[valueReference[0]][valueReference[1]]["value"] = inputElement.prop('value');
            });
        }
        $(presentElement).click(onClickFunction);
        onClickFunction();
    }

    initField(
        presentElementId,
        requestBodyId,
        inputElementId,
        valueReference = null,
    ) {
        let parent = this;
        let presentElement = $(presentElementId);
        let inputElement = $(inputElementId);
        let requestBodyElement = $(requestBodyId);
        inputElement.prop("value", parent.pars[valueReference]["value"]);
        presentElement.prop("checked", parent.pars[valueReference]["valuePresent"]);
        requestBodyElement.prop("checked", parent.pars[valueReference]["requestBody"]);
        requestBodyElement.click(function () {
            let isChecked = presentElement.prop('checked');
            let isRbchecked = requestBodyElement.prop("checked");
            let disabled = !(isChecked || isRbchecked);
            inputElement.prop('disabled', disabled);
            if (disabled) {
                inputElement.prop('value', '');
            }
            else {
                inputElement.prop('value', parent.pars[valueReference]["value"]);
            }
            parent.pars[valueReference]["requestBody"] = requestBodyElement.prop("checked");
        });
        let onClickFunction = function () {
            let isChecked = presentElement.prop('checked');
            let isRbchecked = requestBodyElement.prop("checked");
            let disabled = !(isChecked || isRbchecked);
            inputElement.prop('disabled', disabled);
            if (disabled) {
                inputElement.prop('value', '');
            }
            else {
                inputElement.prop('value', parent.pars[valueReference]["value"]);
            }
        };
        if (valueReference != null) {
            inputElement.change(function () {
                parent.pars[valueReference]["value"] = inputElement.prop('value');
            });
        }
        $(presentElement).click(onClickFunction);
        onClickFunction();
    }

    static hide() {
        $('#oidc-build-authn').hide();
    }

    static scrollTo() {
        let oidcBuildAuthnDiv = $('#oidc-build-authn');
        oidcBuildAuthnDiv.show();
        let pos = oidcBuildAuthnDiv.offset().top - 38;
        $('html, body').animate({scrollTop: pos}, 'slow');
    }

    getAuthnRequestParameters() {
        this.pars.op = OIDC_STATE.getSelectedOp();
        this.pars.rp = OIDC_STATE.getSelectedRp();
        return this.pars;
    }

    /**
     * Updates the authentication request view and returns the parameters that (may) have been modified by the user.
     * @returns {any} AuthnRequest parameters
     */
    readAndGetAuthnRequestParameters() {
        return this.pars;
    }

    initRequestObjectOptions() {
        this.initModuleCheckbox('#oidc-advanced-request-object-options', '#oidc-request-options', "requestObject");
        this.initServerGeneratedField(
            "#oidc-request-issuer-input",
            "#oidc-request-issuer-button",
            "#oidc-request-issuer-request-body",
            "#oidc-request-issuer-present",
            ["requestObject", "issuer"]
        );

        this.initServerGeneratedField(
            "#oidc-request-aud-input",
            "#oidc-request-aud-button",
            "#oidc-request-aud-request-body",
            "#oidc-request-aud-present",
            ["requestObject", "audience"]
        );

        $("#oidc-request-issuer-request-body").prop("disabled", true);
        $("#oidc-request-aud-request-body").prop("disabled", true);

        let parent = this;
        let signRequestCheckbox = $("#oidc-request-sign-request-body");
        signRequestCheckbox.prop("checked", parent.pars["requestObject"]["signRequest"]);
        signRequestCheckbox.click(function () {
            parent.pars["requestObject"]["signRequest"] = signRequestCheckbox.prop("checked");
        });
        let encryptRequestCheckbox = $("#oidc-request-encrypt-request-body");
        encryptRequestCheckbox.prop("checked", parent.pars["requestObject"]["encryptRequest"]);
        encryptRequestCheckbox.click(function () {
            parent.pars["requestObject"]["encryptRequest"] = encryptRequestCheckbox.prop("checked");
        });

        let inRequestBodyCheckbox = $("#oidc-request-claims-request-body");
        inRequestBodyCheckbox.prop("checked", parent.pars["claimInRequestBody"]);
        inRequestBodyCheckbox.click(function () {
            parent.pars["claimInRequestBody"] = inRequestBodyCheckbox.prop("checked");
        });
    }

    initModuleCheckbox(
        checkboxSelector,
        optionsSelector,
        moduleReference) {
        let parent = this;
        let requestOptions = $(checkboxSelector);
        requestOptions.prop("checked", parent.pars[moduleReference]["moduleEnabled"]);
        let clickFunction = function () {
            let checked = requestOptions.prop("checked");
            parent.pars[moduleReference]["moduleEnabled"] = checked;
            if (checked) {
                $(optionsSelector).show();
            }
            else {
                $(optionsSelector).hide();
            }
        };
        requestOptions.click(clickFunction);
        clickFunction();
    }

    initServerGeneratedField(
        inputSelector,
        buttonSelector,
        requestBodySelector,
        fieldPresentSelector,
        valueReference
    ) {
        let input = $(inputSelector);
        let requestBodyCheckbox = $(requestBodySelector);
        let fieldPresentCheckbox = $(fieldPresentSelector);
        let parent = this;
        requestBodyCheckbox.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["requestBody"]);
        requestBodyCheckbox.click(function () {
            parent.pars[valueReference[0]][valueReference[1]]["requestBody"] = requestBodyCheckbox.prop("checked");
        });
        fieldPresentCheckbox.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["valuePresent"]);
        fieldPresentCheckbox.click(function () {
            parent.pars[valueReference[0]][valueReference[1]]["valuePresent"] = fieldPresentCheckbox.prop("checked");
        });
        input.prop("value", parent.pars[valueReference[0]][valueReference[1]]["value"]);
        input.prop("disabled", true);
        $(buttonSelector).click(function () {
            input.prop("disabled", false);
        })
        input.change(function () {
            parent.pars[valueReference[0]][valueReference[1]]["value"] = input.prop("value");
        })
    }

    initAdvancedOptions() {
        this.initModuleCheckbox(
            "#oidc-advanced-authn-options",
            "#oidc-advanced-authn-request",
            "advanced"
        );
        this.initServerGeneratedField(
            "#oidc-request-state-input",
            "#oidc-request-state-button",
            "#oidc-request-state-request-body",
            "#oidc-request-state-present",
            ["advanced", "state"]
        );
        this.initServerGeneratedField(
            "#oidc-request-nonce-input",
            "#oidc-request-nonce-button",
            "#oidc-request-nonce-request-body",
            "#oidc-request-nonce-present",
            ["advanced", "nonce"]
        );
        this.initModuleSelector(
            "#oidc-request-prompt-select",
            "#oidc-request-prompt-request-body",
            "#oidc-request-prompt-present",
            ["advanced", "prompt"]
        );
        this.initServerGeneratedField(
            "#oidc-request-code_challenge-input",
            "#oidc-request-code_challenge-button",
            "#oidc-request-code_challenge-request-body",
            "#oidc-request-code_challenge-present",
            ["advanced", "codeChallenge"]
        );
        this.initNestedField(
            '#oidc-request-login_hint-present',
            '#oidc-request-login_hint-request-body',
            '#oidc-request-login_hint-input',
            ["advanced", "loginHint"]
        );
        this.initModuleSelector(
            "#oidc-request-responsetype-select",
            "#oidc-request-responsetype-request-body",
            "#oidc-request-responsetype-present",
            ["advanced", "responseType"]
        );
        this.initModuleSelector(
            "#oidc-request-code_challenge_method-select",
            "#oidc-request-code_challenge_method-request-body",
            "#oidc-request-code_challenge_method-present",
            ["advanced", "codeChallengeMethod"]
        );
    }

    initKeyOptions() {
        this.initModuleCheckbox(
            "#oidc-advanced-keys-request-check",
            "#oidc-advanced-keys-request",
            "keys"
        );
        let signKeySelector = $("#oidc-request-advanced-signkey-select");
        signKeySelector.empty();
        this.pars["keys"]["signKeys"].forEach(key => {
            let description = key["alg"] + " Kid: " + key["kid"];
            if (key["description"] !== null) {
                description = description + " " + key["description"];
            }
            signKeySelector.append('<option value="' + key["kid"] + '">' + description + '</option>')
        });
        signKeySelector.val(this.pars["keys"]["signKey"]);
        signKeySelector.change(function () {
            this.pars["keys"]["signKey"] = signKeySelector.val();
        });
        let encryptionKeySelector = $("#oidc-request-advanced-enckey-select");
        encryptionKeySelector.empty();
        this.pars["keys"]["encKeys"].forEach(key => {
            let description = key["alg"] + " Kid: " + key["kid"];
            if (key["description"] !== null) {
                description = description + " " + key["description"];
            }
            encryptionKeySelector.append('<option value="' + key["kid"] + '">' + description + '</option>')
        });
        encryptionKeySelector.val(this.pars["keys"]["encKey"]);
        encryptionKeySelector.change(function () {
            this.pars["keys"]["encKey"] = encryptionKeySelector.val();
        });
    }

    initModuleSelector(
        inputSelector,
        requestBodySelector,
        presentSelector,
        valueReference) {

        let inputSelect = $(inputSelector);
        let parent = this;
        inputSelect.val(parent.pars[valueReference[0]][valueReference[1]]["value"]);
        inputSelect.change(function () {
            parent.pars[valueReference[0]][valueReference[1]]["value"] = inputSelect.val();
        })
        let requestBodyCheckbox = $(requestBodySelector);
        requestBodyCheckbox.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["requestBody"]);
        requestBodyCheckbox.click(function () {
            parent.pars[valueReference[0]][valueReference[1]]["requestBody"] = requestBodyCheckbox.prop("checked");
        })
        let presentCheckbox = $(presentSelector);
        presentCheckbox.prop("checked", parent.pars[valueReference[0]][valueReference[1]]["valuePresent"]);
        presentCheckbox.click(function () {
            parent.pars[valueReference[0]][valueReference[1]]["valuePresent"] = presentCheckbox.prop("checked");
        })
    }
}
