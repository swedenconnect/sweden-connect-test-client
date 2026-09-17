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
                           (pars, method) => this.onSendAuthnRequest(pars, method)
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
     * @param method the HTTP method to send the request with, 'GET' or 'POST'
     */
    onSendAuthnRequest(authnRequest, method) {
        $.ajax({
                   url: buildUrl('/oidc/authn/generate?method=' + encodeURIComponent(method)),
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

    /**
     * Gets the authentication request as it was sent. A result saved before the method was recorded holds only the URL
     * of a GET request.
     * @param authorizationRequest the sent request of the result
     * @returns {{method: string, url: string, parameters: object}|null} the sent request
     */
    static sentRequest(authorizationRequest) {
        if (!authorizationRequest) {
            return null;
        }
        if (typeof authorizationRequest === 'string') {
            return { method: 'GET', url: authorizationRequest, parameters: null };
        }
        return authorizationRequest;
    }

    /**
     * Gets form parameters for display - a parameter with a single value is shown as that value.
     * @param parameters the form parameters, each name mapped to its values
     * @returns {object} the parameters for display
     */
    static formParameters(parameters) {
        const result = {};
        for (const [name, values] of Object.entries(parameters || {})) {
            result[name] = Array.isArray(values) && values.length === 1 ? values[0] : values;
        }
        return result;
    }

    /**
     * Gets the value of the request parameter - the request object - of the authentication request as it was sent: from
     * the query string for GET and from the form parameters for POST.
     * @param sentRequest the sent request, see sentRequest()
     * @returns {string|null} the request parameter, or null if the request has none
     */
    static requestParameter(sentRequest) {
        if (!sentRequest) {
            return null;
        }
        if (sentRequest.method === 'POST') {
            const values = (sentRequest.parameters || {})['request'];
            const value = Array.isArray(values) ? values[0] : values;
            return typeof value === 'string' ? value : null;
        }
        try {
            return new URL(sentRequest.url).searchParams.get('request');
        }
        catch (e) {
            return null;
        }
    }

    /**
     * Decodes a signed or unsigned JWT into its header and claims. Nothing is verified.
     * @param jwt the serialized JWT
     * @returns {{header: object, claims: object}|null} the header and claims, or null if the value is not a signed or
     *     unsigned JWT - e.g., an encrypted JWT, or a value that cannot be read as a JWT
     */
    static decodeRequestObject(jwt) {
        if (typeof jwt !== 'string') {
            return null;
        }
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            // An encrypted JWT has five parts
            return null;
        }
        const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
        try {
            const header = JSON.parse(OIDCAuthenticationResult.base64UrlDecode(parts[0]));
            if (!isObject(header) || typeof header.alg !== 'string' || header.enc !== undefined) {
                return null;
            }
            const claims = JSON.parse(OIDCAuthenticationResult.base64UrlDecode(parts[1]));
            return isObject(claims) ? { header: header, claims: claims } : null;
        }
        catch (e) {
            return null;
        }
    }

    /**
     * Decodes a Base64url-encoded UTF-8 string.
     * @param value the encoded value
     * @returns {string} the decoded string
     * @throws Error if the value is not valid Base64url or not valid UTF-8
     */
    static base64UrlDecode(value) {
        if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
            throw new Error('Invalid Base64url');
        }
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
        const bytes = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
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

        const sentRequest = OIDCAuthenticationResult.sentRequest(resultData.authorizationRequest);
        $('#oidc-authn-result-view-authnrequest').click(() => {
            if (!sentRequest) {
                return;
            }
            const request = sentRequest.method === 'POST'
                ? {
                    json: {
                        method: sentRequest.method,
                        endpoint: sentRequest.url,
                        parameters: OIDCAuthenticationResult.formParameters(sentRequest.parameters)
                    }
                }
                : { url: sentRequest.url };
            const requestObject = OIDCAuthenticationResult.decodeRequestObject(
                OIDCAuthenticationResult.requestParameter(sentRequest));
            if (requestObject) {
                codeViewer.displayParts('Authentication Request', [
                    { label: 'Request', ...request },
                    { label: 'Request Object - Header', json: requestObject.header },
                    { label: 'Request Object - Claims', json: requestObject.claims }
                ]);
            }
            else {
                codeViewer.displayParts('Authentication Request', [request]);
            }
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
            if (sentRequest || resultData.requestParameters) {
                const parameters = sentRequest ? { Method: sentRequest.method } : {};
                this.displayAuthnRequestDetails({ ...parameters, ...(resultData.requestParameters || {}) });
            }
        });

        const responseDiv = $('#oidc-authn-result-response');
        const accessTokenDiv = $('#oidc-authn-result-access-token');
        const idTokenDiv = $('#oidc-authn-result-id-token');
        const userInfoDiv = $('#oidc-authn-result-userinfo');
        if (resultData.responseParameters) {
            const tableDiv = responseDiv.find('tbody');
            this.appendProtectionRows(tableDiv, resultData.responseProtection);

            for (var prop in resultData.responseParameters) {
                if (Object.prototype.hasOwnProperty.call(resultData.responseParameters, prop)) {
                    let value = resultData.responseParameters[prop];
                    if (!prop.includes("_token")) {
                        tableDiv.append(this.createRow(prop, value));
                    }
                }
            }
            responseDiv.show();

            const accessTokenButton = $('#oidc-authn-result-view-access-token');
            const rawAccessToken = resultData.accessToken
                || (resultData.response && resultData.response.access_token);
            accessTokenDiv.hide();
            if (rawAccessToken) {
                accessTokenButton.show().off('click').click(() => {
                    const accessTokenTableDiv = accessTokenDiv.find('tbody').empty();
                    const claims = resultData.accessTokenClaims || {};
                    if (Object.keys(claims).length > 0) {
                        for (const prop in claims) {
                            if (Object.prototype.hasOwnProperty.call(claims, prop)) {
                                accessTokenTableDiv.append(this.createRow(prop, claims[prop]));
                            }
                        }
                    }
                    else {
                        accessTokenTableDiv.append(this.createRow('Format', 'Opaque token (not a JWT)'));
                        accessTokenTableDiv.append(this.createRow('access_token', rawAccessToken));
                    }
                    accessTokenDiv.show();
                    accessTokenButton.hide();
                });
            }
            else {
                accessTokenButton.hide();
            }
            const idTokenTableDiv = idTokenDiv.find('tbody');
            this.appendProtectionRows(idTokenTableDiv, resultData.idTokenProtection);
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
            this.displayUserInfo(resultData);
            userInfoDiv.show();

            this.displayScopeValidation(resultData.scopeValidation);
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

        this.initUserInfoRequest(resultData);
    }

    /**
     * Displays the OIDC UserInfo frame - the UserInfo claims, or why there are none. Any previous contents are replaced.
     * A result saved before UserInfo could be skipped holds no userInfoResult, and its claims were received.
     * @param resultData the authentication result
     */
    displayUserInfo(resultData) {
        const tbody = $('#oidc-authn-result-userinfo').find('tbody').empty();
        const result = resultData.userInfoResult;
        const status = result ? result.status : 'RECEIVED';

        if (status === 'NOT_CALLED') {
            tbody.append(this.createTextRow('Note', 'No call was made to the UserInfo endpoint - "Call UserInfo'
                + ' automatically" was not checked. Use "Send UserInfo Request" below to call it.',
                'table-text table-warning'));
            return;
        }
        if (status === 'FAILED') {
            tbody.append(this.createTextRow('Note', result.manual
                ? 'The request sent with "Send UserInfo Request" failed - no UserInfo claims were received.'
                : 'The UserInfo call failed - no UserInfo claims were received.', 'table-text table-danger'));
            tbody.append(this.createTextRow('HTTP Status',
                result.http_status !== null && result.http_status !== undefined
                    ? String(result.http_status) : 'No response'));
            if (result.www_authenticate) {
                tbody.append(this.createTextRow('WWW-Authenticate', result.www_authenticate));
            }
            if (result.body) {
                tbody.append(this.createTextRow('Response Body', result.body));
            }
            if (result.error) {
                tbody.append(this.createTextRow('Error', result.error));
            }
            return;
        }

        if (result && result.manual) {
            tbody.append(this.createTextRow('Source', 'Received with "Send UserInfo Request"'));
        }
        this.appendProtectionRows(tbody, resultData.userInfoProtection);
        for (const prop in resultData.userInfoClaims) {
            if (Object.prototype.hasOwnProperty.call(resultData.userInfoClaims, prop)) {
                tbody.append(this.createRow(prop, resultData.userInfoClaims[prop]));
            }
        }
        for (const prop in resultData.missingUserInfoClaims) {
            if (Object.prototype.hasOwnProperty.call(resultData.missingUserInfoClaims, prop)) {
                tbody.append(this.createRow(prop, "Requested value " + prop + " was missing in Userinfo.",
                                            'table-text table-danger',
                                            'table-text table-danger'));
            }
        }
    }

    /**
     * Sets up the "Send UserInfo Request" frame. It is shown on every result except an OP error.
     * @param resultData the authentication result
     */
    initUserInfoRequest(resultData) {
        const frame = $('#oidc-authn-result-userinfo-request');
        if (resultData.op_error) {
            frame.hide();
            return;
        }
        $('#oidc-userinfo-request-access-token').val(
            resultData.accessToken || (resultData.response && resultData.response.access_token) || '');
        $('#oidc-userinfo-request-method-get').prop('checked', true);
        $('#oidc-userinfo-request-send-button').off('click').click(() => this.sendUserInfoRequest(resultData));
        frame.show();
    }

    /**
     * Sends a UserInfo request (made by the backend), shows the request and response in the JSON viewer and, if the
     * authentication result could be evaluated against the response, updates the UserInfo frame and the scope
     * validation. Errors are only shown in the viewer.
     * @param resultData the authentication result
     */
    sendUserInfoRequest(resultData) {
        const request = {
            access_token: $('#oidc-userinfo-request-access-token').val(),
            method: $('input[name="oidc-userinfo-request-method"]:checked').val() || 'GET'
        };
        const button = $('#oidc-userinfo-request-send-button').prop('disabled', true);
        $.ajax({
                   url: buildUrl('/oidc/authn/userinfo'),
                   type: 'POST',
                   contentType: 'application/json',
                   data: JSON.stringify(request),
                   dataType: 'json',
                   success: (result) => {
                       const evaluation = result.evaluation;
                       if (evaluation) {
                           resultData.userInfoResult = evaluation.userInfoResult || null;
                           resultData.userInfoClaims = evaluation.userInfoClaims || null;
                           resultData.userInfoProtection = evaluation.userInfoProtection || null;
                           resultData.missingUserInfoClaims = evaluation.missingUserInfoClaims || null;
                           resultData.scopeValidation = evaluation.scopeValidation || null;
                           OIDC_STATE.setAuthnResult(resultData);
                           this.displayUserInfo(resultData);
                           $('#oidc-authn-result-userinfo').show();
                           this.displayScopeValidation(resultData.scopeValidation);
                       }
                       codeViewer.displayParts('UserInfo Request',
                                               OIDCAuthenticationResult.userInfoExchangeParts(result.exchange || {}));
                   },
                   error: (error) => {
                       const reason = error && error.status
                           ? 'the test client answered ' + error.status + ' ' + (error.statusText || '')
                           : 'no response from the test client';
                       codeViewer.displayParts('UserInfo Request', [
                           { label: 'Error', text: 'The UserInfo request could not be sent: ' + reason }
                       ]);
                   },
                   complete: () => {
                       button.prop('disabled', false);
                   }
               });
    }

    /**
     * Gets the parts that a UserInfo request is shown with in the JSON viewer - the request as sent, the response
     * status, headers and raw body, and the claims and protection if the body could be read.
     * @param exchange the UserInfo request and response, as reported by the server
     * @returns {object[]} the parts, see CodeViewer.displayParts()
     */
    static userInfoExchangeParts(exchange) {
        const parts = [];
        if (exchange.request) {
            parts.push({ label: 'Request', json: exchange.request });
        }
        if (exchange.error) {
            parts.push({ label: 'Error', text: exchange.error });
        }
        if (exchange.status !== null && exchange.status !== undefined) {
            parts.push({ label: 'Response Status', text: String(exchange.status) });
            parts.push({ label: 'Response Headers', json: exchange.response_headers || {} });
            parts.push({ label: 'Response Body', text: exchange.body ? exchange.body : '(empty)' });
        }
        if (exchange.claims) {
            parts.push({ label: 'UserInfo Claims', json: exchange.claims });
        }
        if (exchange.protection) {
            parts.push({ label: 'UserInfo Protection', json: exchange.protection });
        }
        return parts;
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

    /**
     * Displays, per requested scope, the claims the scope is defined to deliver and whether they were received.
     *
     * @param scopeValidation the validation results reported by the server
     */
    displayScopeValidation(scopeValidation) {
        const card = $('#oidc-authn-result-scope-validation');
        const tbody = $('#oidc-scope-validation-tbody').empty();
        if (!scopeValidation || scopeValidation.length === 0) {
            card.hide();
            return;
        }

        const statusClass = {
            OK:        'table-text table-success',
            MISSING:   'table-text table-danger',
            WARNING:   'table-text table-warning',
            UNKNOWN:   'table-text text-muted',
            NO_CLAIMS: 'table-text text-muted',
            NOT_CHECKED: 'table-text text-muted'
        };
        const statusText = {
            OK:        'All claims of the scope were received',
            MISSING:   'Claims are missing',
            WARNING:   'Delivered, but not as specified',
            UNKNOWN:   'Unknown scope - not validated',
            NO_CLAIMS: 'The scope does not deliver any claims',
            NOT_CHECKED: 'The claims expected from UserInfo were not checked'
        };

        for (const result of scopeValidation) {
            const cls = statusClass[result.status] || 'table-text';
            tbody.append(this.createRow(result.scope, result.message || statusText[result.status] || '', cls, cls));

            const oneOfSatisfied = (result.claims || [])
                .some(c => c.requirement === 'ONE_OF' && c.received);

            for (const claim of (result.claims || [])) {
                const expected = claim.requirement !== 'OPTIONAL'
                    && !(claim.requirement === 'ONE_OF' && oneOfSatisfied);
                let rowClass = 'table-text';
                if (!claim.received) {
                    rowClass = expected && !claim.notCheckedReason ? 'table-text table-danger' : 'table-text text-muted';
                }
                const requirement = claim.requirement === 'ONE_OF' ? 'one of' : claim.requirement.toLowerCase();
                const expectation = ' (expected in ' + claim.expectedLocation + ', ' + requirement + ')';
                let received = 'Not received' + expectation;
                if (claim.received) {
                    received = 'Received in ' + claim.receivedIn;
                }
                else if (claim.notCheckedReason) {
                    received = 'Not checked, ' + claim.notCheckedReason + expectation;
                }
                tbody.append(this.createRow('\u00a0\u00a0\u00a0\u00a0' + claim.claim, received, rowClass, rowClass));
            }
        }
        card.show();
    }

    /**
     * Appends rows telling how an object was delivered - signed or not, encrypted or not - along with the
     * JOSE parameters used.
     *
     * @param tbody the table body to append the rows to
     * @param protection the protection information, as reported by the server
     */
    appendProtectionRows(tbody, protection) {
        if (!protection) {
            return;
        }
        const box = (checked) => checked ? '&#9745;' : '&#9744;';
        const describe = (checked, label, params) => {
            const assigned = params.filter(p => p[1]).map(p => p[0] + ': ' + p[1]);
            return box(checked) + ' ' + label + (assigned.length > 0 ? ' (' + assigned.join(', ') + ')' : '');
        };

        tbody.append(this.createRow('Signature',
            describe(protection.signed, protection.signed ? 'Signed' : 'Not signed', [
                ['alg', protection.signatureAlgorithm],
                ['kid', protection.signatureKeyId],
                ['typ', protection.signatureType]
            ])));
        tbody.append(this.createRow('Encryption',
            describe(protection.encrypted, protection.encrypted ? 'Encrypted' : 'Not encrypted', [
                ['alg', protection.encryptionAlgorithm],
                ['enc', protection.encryptionMethod],
                ['kid', protection.encryptionKeyId]
            ])));
        if (protection.format) {
            tbody.append(this.createRow('Delivery', protection.format));
        }
        if (protection.note) {
            tbody.append(this.createRow('Note', protection.note));
        }
    }

    /**
     * Creates a table row whose contents are shown as text - for values that come from the OP.
     * @param title the row title
     * @param text the contents
     * @param cls the class of the row cells
     * @returns {*|jQuery} the row
     */
    createTextRow(title, text, cls = 'table-text') {
        return $('<tr>')
            .append($('<th>', { scope: 'row', class: cls, text: title }))
            .append($('<td>', { class: cls, text: text }));
    }

    createRow(title, contents, thClass = 'table-text', tdClass = 'table-text') {

        let html = "";
        if (Array.isArray(contents)) {
            html = contents.map(pair => Array.isArray(pair)
                ? (pair.length === 1 ? pair[0] : `${pair[0]}: ${pair[1] || 'Not assigned'}`)
                : pair)
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

        // Shown for the selected RP only if the server reports that it has an Entity Configuration.
        $('#oidc-view-ec').hide();

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

        $('#oidc-view-ec').click(function () {
            let entityId = $(this).val();
            $.ajax({
                       url: $(this).data('url'),
                       type: 'GET',
                       data: {
                           plain: true
                       },
                       success: (statement) => {
                           codeViewer.displayJson(entityId, statement);
                       },
                       error: (error) => {
                           console.error("Failed to get entity configuration: " + JSON.stringify(error));
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
            $('#oidc-rp-info').hide();
            $('#oidc-authn-next-button').prop('disabled', true);
        }
        else {
            for (const rp of this.oidcInfoCache.rps) {
                if (rp.entity_id === entityId) {
                    $('#oidc-rp-description').text(rp.description);
                    let rpUrl = $('#oidc-metadata-url');
                    rpUrl.attr('href', rp.metadata_url);
                    rpUrl.text(rp.metadata_url);
                    $('#oidc-view-metadata').attr('value', rp.entity_id);
                    let viewEc = $('#oidc-view-ec');
                    viewEc.attr('value', rp.entity_id);
                    if (rp.entity_configuration_url) {
                        viewEc.data('url', rp.entity_configuration_url);
                        viewEc.show();
                    }
                    else {
                        viewEc.removeData('url');
                        viewEc.hide();
                    }
                    $('#oidc-rp-info').show();

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
        // Rebuild the list - OP:s may have been added since the last time (for example by resolving them from the
        // federation).
        const previous = opSelect.val();
        $('#oidc-op-info').hide();
        opSelect.empty();
        opSelect.append(new Option("--- Select OP ---", "none", true, false));
        for (const op of opInfo) {
            opSelect.append(new Option(op.entity_id, op.entity_id, false, false));
        }
        if (previous && opInfo.some(op => op.entity_id === previous)) {
            opSelect.val(previous);
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
            $('#oidc-op-info').hide();
            $('#oidc-authn-next-button').prop('disabled', true);
        }
        else {
            for (const op of this.oidcInfoCache.ops) {
                if (op.entity_id === entityId) {
                    $('#oidc-op-displayname').text(op.display_name);
                    $('#oidc-op-description').text(op.description);
                    $('#oidc-op-info').show();

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

    /** Enabled parameters go in the request URL. */
    static MODE_REQUEST = 'request';

    /** Enabled parameters go in the request object - client_id, response_type and scope also in the URL. */
    static MODE_REQUEST_BODY = 'requestBody';

    /** The scope requesting a signature, for which tbs_data is included by default. */
    static SCOPE_SIGN = 'https://id.oidc.se/scope/sign';

    /** The scope requesting a signature approval, for which tbs_data is excluded by default. */
    static SCOPE_SIGN_APPROVAL = 'https://id.oidc.se/scope/signApproval';

    /**
     * Gets the name of a message member in the user message and sign message objects.
     * @param langCode the language code, or null for a message without language code
     * @returns {string} the member name
     */
    static messageKey(langCode) {
        return langCode ? 'message#' + langCode : 'message';
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

    static addSelectedAcrValue(list, uri) {
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

    static SCOPE_URIS = [
        "https://id.oidc.se/scope/naturalPersonInfo",
        "https://id.oidc.se/scope/naturalPersonNumber",
        "https://id.oidc.se/scope/naturalPersonOrgId",
        "https://id.oidc.se/scope/sign",
        "https://id.oidc.se/scope/signApproval",
        "https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity",
        "https://id.swedenconnect.se/scope/eidasSwedishIdentity"
    ];

    static addSelectedScopeValue(list, uri) {
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
        this.initTemplates();
        this.initModeButtons();
        this.initRequestObjectOptions();
        this.initAdvancedOptions();
        this.initKeyOptions();
        let parent = this;
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
                parent.switchOnClaims();
                addClaimFunction('id', $('#oidc-id-claims-table').children().length);
            });

        this.initScopeValues();

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

        this.initAcrValues(this.pars.acrValues);

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

        // The method is chosen by the button, and is not part of the request that is built
        $('#oidc-request-submit-get-button').off('click').click(() => {
            this.sendAuthnRequestCallback(this.readAndGetAuthnRequestParameters(), 'GET');
        });
        $('#oidc-request-submit-post-button').off('click').click(() => {
            this.sendAuthnRequestCallback(this.readAndGetAuthnRequestParameters(), 'POST');
        });

        $('#oidc-request-export-button').click(() => {
            this.export();
        });

        this.initCallUserInfo();

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
        let rbCheckbox = $('#oidc-request-um-request-body');
        let um64 = $('#oidc-request-um-b64');
        um64.change(function () {
            parent.pars["userMessage"]["b64Encode"] = this.checked;
        });
        umCheckbox.change(function () {
            umDiv.toggle(this.checked || rbCheckbox.prop("checked"));
            parent.pars["userMessage"]["valuePresent"] = this.checked;
        });
        rbCheckbox.change(function () {
            umDiv.toggle(umCheckbox.prop("checked") || this.checked);
            parent.pars["userMessage"]["requestBody"] = this.checked;
        });
        let umMimeType = $('#oidc-request-um-mimetype-select');
        umMimeType.change(function () {
            parent.pars["userMessage"]["mime_type"] = umMimeType.val() || null;
        });
        this.refreshUserMessage();

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
        let sigb64Checkbox = $('#oidc-request-sig-b64');
        let sigRbCheckbox = $('#oidc-request-sig-request-body');
        sigb64Checkbox.change(function () {
            parent.pars["signMessage"]["b64Encode"] = this.checked;
        });
        sigCheckbox.change(function () {
            parent.pars["signMessage"]["valuePresent"] = this.checked;
            parent.updateSignMessageView(true);
        });
        sigRbCheckbox.change(function () {
            parent.pars["signMessage"]["requestBody"] = this.checked;
            parent.updateSignMessageView(true);
        });

        let sigMimeType = $('#oidc-request-sig-mimetype-select');
        sigMimeType.change(function () {
            parent.signMessageObject()["mime_type"] = sigMimeType.val() || null;
        });

        let tbsTextarea = $('#oidc-request-tbs-textarea');
        tbsTextarea.on('input change', function () {
            parent.pars["signMessage"]["tbsData"] = tbsTextarea.prop('value');
        });
        $('#oidc-request-tbs-include').change(function () {
            parent.pars["signMessage"]["includeTbsData"] = this.checked;
            tbsTextarea.prop('disabled', !this.checked);
        });

        let sigJwtSign = $('#oidc-request-sig-jwt-sign');
        let sigJwtSignKey = $('#oidc-request-sig-jwt-signkey-select');
        sigJwtSignKey.empty();
        (this.pars["keys"]["signKeys"] || []).forEach(key => {
            let description = key["alg"] + " Kid: " + key["kid"];
            if (key["description"] !== null && key["description"] !== undefined) {
                description = description + " " + key["description"];
            }
            sigJwtSignKey.append($('<option>', { value: key["kid"], text: description }));
        });
        sigJwtSign.change(function () {
            parent.pars["signMessage"]["signJwt"] = this.checked;
            sigJwtSignKey.prop('disabled', !this.checked);
        });
        sigJwtSignKey.change(function () {
            parent.pars["signMessage"]["signKey"] = sigJwtSignKey.val();
        });
        $('#oidc-request-sig-jwt-encrypt').change(function () {
            parent.pars["signMessage"]["encryptJwt"] = this.checked;
        });

        this.refreshSignMessage();
    }

    /**
     * Gets the sign message object of the sign request - the messages and their MIME type - creating it if missing.
     * @returns {object} the sign message object
     */
    signMessageObject() {
        if (!this.pars.signMessage.signMessage) {
            this.pars.signMessage.signMessage = {};
        }
        return this.pars.signMessage.signMessage;
    }

    /**
     * Tells whether tbs_data should be included according to the scope. Both the URL scope and the request object
     * scope are considered: tbs_data is included if https://id.oidc.se/scope/sign is present, excluded if
     * https://id.oidc.se/scope/signApproval is present without it, and included if neither is present.
     * @returns {boolean} whether tbs_data should be included
     */
    tbsDataIncludedByScope() {
        const scopes = new Set();
        for (const value of [this.pars.scope ? this.pars.scope.value : null, this.pars.requestBodyScope]) {
            (value || '').split(/\s+/).filter(s => s).forEach(s => scopes.add(s));
        }
        if (scopes.has(OIDCAuthnRequest.SCOPE_SIGN)) {
            return true;
        }
        return !scopes.has(OIDCAuthnRequest.SCOPE_SIGN_APPROVAL);
    }

    /**
     * Shows the sign message area when the sign request is placed anywhere, and the settings of the JWT that carries
     * the sign request when it is placed in the URL. When the area is expanded the "TBS Data" box may be set from the
     * scope, see tbsDataIncludedByScope().
     * @param applyScopeRule true to set the "TBS Data" box from the scope if the area goes from hidden to shown
     */
    updateSignMessageView(applyScopeRule) {
        const sig = this.pars.signMessage;
        const sigDiv = $('#oidc-request-sig-div');
        const expanded = !!(sig.valuePresent || sig.requestBody);
        const wasHidden = sigDiv.prop('hidden');
        sigDiv.prop('hidden', !expanded);
        $('#oidc-request-sig-jwt-div').prop('hidden', !sig.valuePresent);
        if (applyScopeRule && expanded && wasHidden) {
            sig.includeTbsData = this.tbsDataIncludedByScope();
            $('#oidc-request-tbs-include').prop('checked', sig.includeTbsData);
            $('#oidc-request-tbs-textarea').prop('disabled', !sig.includeTbsData);
        }
    }

    /**
     * Gets the boxes that an enabled row gets in a mode.
     * @param mode the mode
     * @param alsoInRequest true for the rows that stay in the URL in "In Request Body" mode (client_id, response_type
     *     and scope - OpenID Connect Core 1.0, section 6.1)
     * @returns {{valuePresent: boolean, requestBody: boolean}} the "In Request" and "In Request Body" boxes
     */
    static placement(mode, alsoInRequest = false) {
        return mode === OIDCAuthnRequest.MODE_REQUEST_BODY
            ? {valuePresent: alsoInRequest, requestBody: true}
            : {valuePresent: true, requestBody: false};
    }

    /**
     * Gets the active mode. Requests exported before the modes existed are in "In Request" mode.
     * @returns {string} the mode
     */
    getMode() {
        return this.pars.requestMode === OIDCAuthnRequest.MODE_REQUEST_BODY
            ? OIDCAuthnRequest.MODE_REQUEST_BODY
            : OIDCAuthnRequest.MODE_REQUEST;
    }

    /**
     * Gets the rows with the two boxes that are moved by the mode buttons, except the claims row whose "In Request"
     * box is not part of this.pars. The issuer and audience of the request object options are not included.
     * @returns {[object, boolean][]} each row's parameter object and whether it stays in the URL in body mode
     */
    placementRows() {
        const adv = this.pars.advanced;
        return [
            [this.pars.clientId, true],
            [this.pars.redirectUri, false],
            [this.pars.scope, true],
            [this.pars.acrValues, false],
            [adv.prompt, false],
            [adv.responseType, true],
            [adv.state, false],
            [adv.nonce, false],
            [adv.loginHint, false],
            [adv.codeChallengeMethod, false],
            [adv.codeChallenge, false],
            [this.pars.userMessage, false],
            [this.pars.signMessage, false]
        ];
    }

    /**
     * Initializes the "In Request-mode" and "In Request Body-mode" buttons.
     */
    initModeButtons() {
        this.pars.requestMode = this.getMode();
        $('#oidc-request-mode-request').off('click').on('click', () => {
            this.applyMode(OIDCAuthnRequest.MODE_REQUEST);
        });
        $('#oidc-request-mode-request-body').off('click').on('click', () => {
            this.applyMode(OIDCAuthnRequest.MODE_REQUEST_BODY);
        });
        this.updateModeButtons();
    }

    /**
     * Marks the button of the active mode.
     */
    updateModeButtons() {
        const inRequestBody = this.getMode() === OIDCAuthnRequest.MODE_REQUEST_BODY;
        $('#oidc-request-mode-request')
            .toggleClass('active', !inRequestBody)
            .attr('aria-pressed', String(!inRequestBody));
        $('#oidc-request-mode-request-body')
            .toggleClass('active', inRequestBody)
            .attr('aria-pressed', String(inRequestBody));
    }

    /**
     * Activates a mode: every enabled row - a row with at least one box checked - gets the boxes of the mode, and the
     * request object options are turned on in "In Request Body" mode and off in "In Request" mode. Rows with no box
     * checked stay off.
     * @param mode the mode
     */
    applyMode(mode) {
        this.pars.requestMode = mode;

        for (const [par, alsoInRequest] of this.placementRows()) {
            if (par && (par.valuePresent || par.requestBody)) {
                Object.assign(par, OIDCAuthnRequest.placement(mode, alsoInRequest));
            }
        }
        const claimsPresent = $('#oidc-request-claims-present');
        const claimsRequestBody = $('#oidc-request-claims-request-body');
        if (claimsPresent.prop('checked') || claimsRequestBody.prop('checked')) {
            const placement = OIDCAuthnRequest.placement(mode);
            claimsPresent.prop('checked', placement.valuePresent);
            claimsRequestBody.prop('checked', placement.requestBody);
            this.pars.claimInRequestBody = placement.requestBody;
        }
        this.pars.requestObject.moduleEnabled = mode === OIDCAuthnRequest.MODE_REQUEST_BODY;

        this.refreshField('#oidc-request-client_id-present', '#oidc-request-client_id-request-body',
            '#oidc-request-client_id-input', 'clientId');
        this.refreshField('#oidc-request-redirect-present', '#oidc-request-redirect-request-body',
            '#oidc-request-redirect-input', 'redirectUri');
        this.refreshScopeValues();
        this.refreshAcrValues();
        this.refreshAdvanced();
        this.refreshRequestObject();
        $('#oidc-request-um-present').prop('checked', this.pars.userMessage.valuePresent || false);
        $('#oidc-request-um-request-body').prop('checked', this.pars.userMessage.requestBody || false);
        $('#oidc-request-sig-present').prop('checked', this.pars.signMessage.valuePresent || false);
        $('#oidc-request-sig-request-body').prop('checked', this.pars.signMessage.requestBody || false);
        this.updateSignMessageView(false);
        this.computeClaims();
        this.updateModeButtons();
    }

    /**
     * Switches a row on or off by itself, e.g., when a value is added or the last one removed. Only the boxes of the
     * active mode are changed - boxes the mode does not use are left as the user set them.
     * @param par the row's parameter object
     * @param on whether to switch the row on or off
     * @param alsoInRequest see placement()
     */
    switchRow(par, on, alsoInRequest = false) {
        const placement = OIDCAuthnRequest.placement(this.getMode(), alsoInRequest);
        if (placement.valuePresent) {
            par.valuePresent = on;
        }
        if (placement.requestBody) {
            par.requestBody = on;
        }
    }

    /**
     * Switches the claims row on, with the boxes of the active mode, if none of its boxes is checked.
     */
    switchOnClaims() {
        const claimsPresent = $('#oidc-request-claims-present');
        const claimsRequestBody = $('#oidc-request-claims-request-body');
        if (claimsPresent.prop('checked') || claimsRequestBody.prop('checked')) {
            return;
        }
        const placement = OIDCAuthnRequest.placement(this.getMode());
        if (placement.valuePresent) {
            claimsPresent.prop('checked', true);
        }
        if (placement.requestBody) {
            claimsRequestBody.prop('checked', true);
            this.pars.claimInRequestBody = true;
        }
    }

    createUserMessageDiv(msg, sig = false) {

        let msgId = generateRandomId();

        let msgDiv = $('<div>', {
            class: 'row mt-4'
        });

        let msgLabel = $('<label>', {
            class: 'col-sm-2',
            'data-langcode': msg.lang_code || '',
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
        let parent = this;
        const key = OIDCAuthnRequest.messageKey(msg.lang_code);
        const messages = () => sig ? parent.signMessageObject() : parent.pars.userMessage;
        textArea.on('input change', function () {
            messages()[key] = textArea.prop('value');
        });
        let textAreaCloseButton = $('<button>', {
            type: 'button',
            class: 'btn-close align-self-start p-2',
            click: function () {
                delete messages()[key];
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

    /**
     * Initializes the "Call UserInfo automatically" setting. A request that does not hold the setting - e.g., one
     * exported before the setting existed - calls UserInfo.
     */
    initCallUserInfo() {
        this.pars.callUserInfo = this.pars.callUserInfo !== false;
        this.refreshCallUserInfo();
        $('#oidc-request-call-userinfo-check').off('change').on('change', (event) => {
            this.pars.callUserInfo = $(event.target).prop('checked');
        });
    }

    /**
     * Updates the "Call UserInfo automatically" checkbox from this.pars.
     */
    refreshCallUserInfo() {
        $('#oidc-request-call-userinfo-check').prop('checked', this.pars.callUserInfo !== false);
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

    /**
     * Sets up a button that shows/hides a block of options. Unlike {@link initModuleCheckbox} this only controls
     * what is displayed - it does not affect what is included in the request.
     *
     * @param buttonSelector the toggle button
     * @param optionsSelector the block of options to show or hide
     * @param moduleReference the module in this.pars keeping the display state
     * @param label what the button calls the options, e.g. "advanced options"
     */
    initDisplayToggleButton(
        buttonSelector,
        optionsSelector,
        moduleReference,
        label) {
        let parent = this;
        let button = $(buttonSelector);
        let apply = function (visible) {
            parent.pars[moduleReference]["moduleEnabled"] = visible;
            visible ? $(optionsSelector).show() : $(optionsSelector).hide();
            button.text((visible ? "Hide " : "Display ") + label);
        };
        button.off("click").click(function () {
            apply(!parent.pars[moduleReference]["moduleEnabled"]);
        });
        apply(parent.pars[moduleReference]["moduleEnabled"] || false);
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
        this.initDisplayToggleButton(
            "#oidc-advanced-authn-options",
            "#oidc-advanced-authn-request",
            "advanced",
            "advanced options"
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
        signKeySelector.change(() => {
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
        encryptionKeySelector.change(() => {
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

    /**
     * Initializes the ACR values element.
     * @param acr the ACR object
     */
    initAcrValues(acr) {
        let oidcRequestAcrCheckbox = $('#oidc-request-acr-present');
        let oidcRequestAcrRequestBodyCheckbox = $('#oidc-request-acr-request-body');

        let oidcRequestAcrList = $('#oidc-request-acr-list');
        let oidcRequestAcrAddDiv = $('#oidc-request-acr-drop-div');
        let oidcRequestAcrCustomDiv = $('#oidc-request-acr-custom-div');

        let parent = this;

        // Helper function to update pars.acrValues.value from the list
        let updateAcrValue = function() {
            let uris = [];
            $('#oidc-request-acr-list li span').each(function() {
                uris.push($(this).text());
            });
            parent.pars.acrValues.value = uris.join(' ');
            parent.switchRow(parent.pars.acrValues, uris.length > 0);
            oidcRequestAcrCheckbox.prop('checked', parent.pars.acrValues.valuePresent || false);
            oidcRequestAcrRequestBodyCheckbox.prop('checked', parent.pars.acrValues.requestBody || false);
        };

        let assignedUris = [];

        if (acr && acr.value) {
            assignedUris = acr.value.split(' ').filter(uri => uri.trim() !== '');
        }

        oidcRequestAcrList.empty();
        for (let uri of assignedUris) {
            OIDCAuthnRequest.addSelectedAcrValue(oidcRequestAcrList, uri);
        }
        if (assignedUris.length === 0) {
            oidcRequestAcrList.append($('<li>')
                .text("-- No URIs assigned --")
                .addClass('list-group-item d-flex justify-content-between align-items-center'));
        }

        oidcRequestAcrAddDiv.empty();
        for (let uri of OIDCAuthnRequest.AUTHN_CONTEXT_CLASS_REF_URIS) {
            let option = $('<a>', {
                href: 'javascript:void(0)',
                class: 'dropdown-item',
                'data-acr-attr': uri,
                text: uri,
                click: function(event) {
                    event.preventDefault();

                    if ($(this).hasClass('disabled')) {
                        return;
                    }

                    oidcRequestAcrCustomDiv.hide();
                    OIDCAuthnRequest.addSelectedAcrValue(oidcRequestAcrList, uri);
                    $(this).addClass('disabled');
                    updateAcrValue();
                }
            });

            if (assignedUris.includes(uri)) {
                option.addClass('disabled');
            }
            oidcRequestAcrAddDiv.append(option);
        }
        oidcRequestAcrAddDiv.append($('<a>', {
            href: 'javascript:void(0)',
            class: 'dropdown-item',
            'data-acr-attr': 'other',
            text: "Enter other URI ...",
            click: function(event) {
                event.preventDefault();
                oidcRequestAcrCustomDiv.show();
            }
        }));

        if (acr) {
            oidcRequestAcrCheckbox.prop('checked', acr.valuePresent || false);
            oidcRequestAcrRequestBodyCheckbox.prop('checked', acr.requestBody || false);
        }
        else {
            oidcRequestAcrCheckbox.prop('checked', false);
            oidcRequestAcrRequestBodyCheckbox.prop('checked', false);
        }

        oidcRequestAcrCheckbox.change(function() {
            parent.pars.acrValues.valuePresent = oidcRequestAcrCheckbox.prop('checked');
        });

        oidcRequestAcrRequestBodyCheckbox.change(function() {
            parent.pars.acrValues.requestBody = oidcRequestAcrRequestBodyCheckbox.prop('checked');
        });

        oidcRequestAcrList.on('click', 'button.btn-close', function() {
            let ul = $(this).closest('ul');
            let uri = $(this).closest('li').find('span').text();
            $(this).closest('li').remove();

            let link = oidcRequestAcrAddDiv.find('a[data-acr-attr="' + uri + '"]');
            if (link.length > 0) {
                link.removeClass('disabled');
            }

            if (ul.children('li').length === 0) {
                ul.append($('<li>')
                    .text("-- No URIs assigned --")
                    .addClass('list-group-item d-flex justify-content-between align-items-center'));
            }
            updateAcrValue();
        });

        $('#oidc-request-acr-custom-button').click(function() {
            let oidcRequestAcrCustom = $('#oidc-request-acr-custom');
            let uri = oidcRequestAcrCustom.val().trim();
            if (uri !== '') {
                OIDCAuthnRequest.addSelectedAcrValue(oidcRequestAcrList, uri);
                oidcRequestAcrCustom.val('');
                oidcRequestAcrCustomDiv.hide();
                updateAcrValue();
            }
        });
    }

    /**
     * Gets the two lines of the scope row. The URL line keeps its values in pars.scope.value and the request body line
     * in pars.requestBodyScope. Each line has its own list and add controls.
     * @returns {{prefix: string, get: function(): string, set: function(string)}[]} the URL line and the body line
     */
    scopeLines() {
        return [
            {
                prefix: '#oidc-request-scope',
                get: () => this.pars.scope.value,
                set: (value) => { this.pars.scope.value = value; }
            },
            {
                prefix: '#oidc-request-scope-body',
                get: () => this.pars.requestBodyScope,
                set: (value) => { this.pars.requestBodyScope = value; }
            }
        ];
    }

    /**
     * Initializes the Scope values element - both scope lines and the scope row's boxes.
     */
    initScopeValues() {
        let parent = this;
        if (this.pars.requestBodyScope === undefined || this.pars.requestBodyScope === null) {
            // Templates and requests exported before the scope had two lines hold a single scope value
            this.pars.requestBodyScope = this.pars.scope.value;
        }
        for (const line of this.scopeLines()) {
            this.initScopeLine(line);
        }

        let oidcRequestScopeCheckbox = $('#oidc-request-scope-present');
        let oidcRequestScopeRequestBodyCheckbox = $('#oidc-request-scope-request-body');
        oidcRequestScopeCheckbox.prop('checked', this.pars.scope.valuePresent || false);
        oidcRequestScopeRequestBodyCheckbox.prop('checked', this.pars.scope.requestBody || false);

        oidcRequestScopeCheckbox.off('change').on('change', function() {
            parent.pars.scope.valuePresent = oidcRequestScopeCheckbox.prop('checked');
        });
        oidcRequestScopeRequestBodyCheckbox.off('change').on('change', function() {
            parent.pars.scope.requestBody = oidcRequestScopeRequestBodyCheckbox.prop('checked');
            parent.updateScopeBodyLine();
        });

        this.scopeBodyLineShown = !!this.pars.scope.requestBody;
        this.updateScopeBodyLine();
    }

    /**
     * Initializes one scope line: its list, its "Add Scope" menu and its custom value input.
     * @param line the scope line, see scopeLines()
     */
    initScopeLine(line) {
        let list = $(line.prefix + '-list');
        let addDiv = $(line.prefix + '-drop-div');
        let customDiv = $(line.prefix + '-custom-div');
        let customInput = $(line.prefix + '-custom');

        let updateScopeValue = function() {
            let uris = [];
            list.find('li span').each(function() {
                uris.push($(this).text());
            });
            line.set(uris.join(' '));
        };

        addDiv.empty();
        for (let uri of OIDCAuthnRequest.SCOPE_URIS) {
            addDiv.append($('<a>', {
                href: 'javascript:void(0)',
                class: 'dropdown-item',
                'data-scope-attr': uri,
                text: uri,
                click: function(event) {
                    event.preventDefault();

                    if ($(this).hasClass('disabled')) {
                        return;
                    }

                    customDiv.hide();
                    OIDCAuthnRequest.addSelectedScopeValue(list, uri);
                    $(this).addClass('disabled');
                    updateScopeValue();
                }
            }));
        }
        addDiv.append($('<a>', {
            href: 'javascript:void(0)',
            class: 'dropdown-item',
            'data-scope-attr': 'other',
            text: "Enter other scope ...",
            click: function(event) {
                event.preventDefault();
                customDiv.show();
            }
        }));

        list.off('click').on('click', 'button.btn-close', function() {
            let ul = $(this).closest('ul');
            let uri = $(this).closest('li').find('span').text();
            $(this).closest('li').remove();

            let link = addDiv.find('a[data-scope-attr="' + uri + '"]');
            if (link.length > 0) {
                link.removeClass('disabled');
            }

            if (ul.children('li').length === 0) {
                ul.append($('<li>')
                    .text("-- No scopes assigned --")
                    .addClass('list-group-item d-flex justify-content-between align-items-center'));
            }
            updateScopeValue();
        });

        $(line.prefix + '-custom-button').off('click').on('click', function() {
            let uri = customInput.val().trim();
            if (uri !== '') {
                OIDCAuthnRequest.addSelectedScopeValue(list, uri);
                customInput.val('');
                customDiv.hide();
                updateScopeValue();
            }
        });

        this.renderScopeLine(line);
    }

    /**
     * Rebuilds the list of a scope line from this.pars without rebinding event handlers.
     * @param line the scope line, see scopeLines()
     */
    renderScopeLine(line) {
        const list = $(line.prefix + '-list');
        const addDiv = $(line.prefix + '-drop-div');
        const value = line.get();
        const assignedUris = value ? value.split(' ').filter(u => u.trim() !== '') : [];

        list.empty();
        for (const uri of assignedUris) {
            OIDCAuthnRequest.addSelectedScopeValue(list, uri);
        }
        if (assignedUris.length === 0) {
            list.append($('<li>')
                .text("-- No scopes assigned --")
                .addClass('list-group-item d-flex justify-content-between align-items-center'));
        }

        addDiv.find('a[data-scope-attr]').removeClass('disabled');
        for (const uri of assignedUris) {
            addDiv.find('a[data-scope-attr="' + uri + '"]').addClass('disabled');
        }
    }

    /**
     * Shows the request body scope line while the scope's "In Request Body" box is checked. Each time the line
     * appears, it starts out with the values of the URL line.
     */
    updateScopeBodyLine() {
        const show = !!this.pars.scope.requestBody;
        if (show && !this.scopeBodyLineShown) {
            this.pars.requestBodyScope = this.pars.scope.value;
        }
        this.scopeBodyLineShown = show;
        this.renderScopeLine(this.scopeLines()[1]);
        $('#oidc-request-scope-body-div').toggle(show);
        $('#oidc-request-scope-url-label').toggle(show);
    }

    /**
     * Loads predefined templates from the server and populates the template dropdown.
     */
    initTemplates() {
        $.ajax({
            url: buildUrl('/templates/oidc-authn-templates.json'),
            type: 'GET',
            dataType: 'json',
            success: (templates) => {
                const dropDiv = $('#oidc-request-template-drop-div');
                dropDiv.empty();
                if (!templates || templates.length === 0) {
                    dropDiv.append($('<span>', { class: 'dropdown-item text-muted', text: 'No templates available' }));
                    return;
                }
                for (const template of templates) {
                    const item = $('<a>', {
                        href: 'javascript:void(0)',
                        class: 'dropdown-item',
                        text: template.name,
                        click: (event) => {
                            event.preventDefault();
                            this.applyTemplate(template);
                        }
                    });
                    if (template.description) {
                        item.attr('title', template.description);
                    }
                    dropDiv.append(item);
                }
            },
            error: () => {
                const dropDiv = $('#oidc-request-template-drop-div');
                dropDiv.empty();
                dropDiv.append($('<span>', { class: 'dropdown-item text-muted', text: 'No templates available' }));
            }
        });
    }

    /**
     * Merges source into target one level deep: plain object values are themselves shallow-merged
     * so that a template specifying only some sub-fields does not wipe out the rest.
     */
    mergeDeep(target, source) {
        const result = { ...target };
        for (const [key, value] of Object.entries(source)) {
            const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
            if (isPlainObject(value) && isPlainObject(target[key])) {
                result[key] = { ...target[key], ...value };
            } else {
                result[key] = value;
            }
        }
        return result;
    }

    /**
     * Applies a predefined template by merging its fields into the current parameters
     * and refreshing the affected UI components.
     * @param template the template object from the JSON file
     */
    applyTemplate(template) {
        if (template.clientId !== undefined) {
            this.pars.clientId = { ...this.pars.clientId, ...template.clientId };
            this.refreshField(
                '#oidc-request-client_id-present',
                '#oidc-request-client_id-request-body',
                '#oidc-request-client_id-input',
                'clientId'
            );
        }
        if (template.redirectUri !== undefined) {
            this.pars.redirectUri = { ...this.pars.redirectUri, ...template.redirectUri };
            this.refreshField(
                '#oidc-request-redirect-present',
                '#oidc-request-redirect-request-body',
                '#oidc-request-redirect-input',
                'redirectUri'
            );
        }
        if (template.scope !== undefined) {
            this.pars.scope = { ...this.pars.scope, ...template.scope };
            // A template holds a single scope value, which goes to both scope lines
            if (template.scope.value !== undefined) {
                this.pars.requestBodyScope = template.scope.value;
            }
            this.refreshScopeValues();
        }
        if (template.acrValues !== undefined) {
            this.pars.acrValues = { ...this.pars.acrValues, ...template.acrValues };
            this.refreshAcrValues();
        }
        if (template.signMessage !== undefined) {
            this.pars.signMessage = this.mergeDeep(this.pars.signMessage, template.signMessage);
            this.refreshSignMessage(template.signMessage.includeTbsData === undefined);
        }
        if (template.userMessage !== undefined) {
            this.pars.userMessage = this.mergeDeep(this.pars.userMessage, template.userMessage);
            this.refreshUserMessage();
        }
        if (template.advanced !== undefined) {
            this.pars.advanced = this.mergeDeep(this.pars.advanced, template.advanced);
            this.refreshAdvanced();
        }
        if (template.requestObject !== undefined) {
            this.pars.requestObject = this.mergeDeep(this.pars.requestObject, template.requestObject);
            this.refreshRequestObject();
        }
        if (template.keys !== undefined) {
            this.pars.keys = { ...this.pars.keys, ...template.keys };
            this.refreshKeys();
        }
        if (template.callUserInfo !== undefined) {
            this.pars.callUserInfo = template.callUserInfo !== false;
            this.refreshCallUserInfo();
        }
        if (template.claims !== undefined || template.claimInRequestBody !== undefined) {
            if (template.claims !== undefined) this.pars.claims = template.claims;
            if (template.claimInRequestBody !== undefined) this.pars.claimInRequestBody = template.claimInRequestBody;
            this.refreshClaims();
        }
    }

    /**
     * Updates a simple text field's UI state from this.pars without rebinding event handlers.
     * @param presentElementId selector for the "In Request" checkbox
     * @param requestBodyId selector for the "In Request Body" checkbox
     * @param inputElementId selector for the text input
     * @param valueReference key in this.pars
     */
    refreshField(presentElementId, requestBodyId, inputElementId, valueReference) {
        const par = this.pars[valueReference];
        const presentElement = $(presentElementId);
        const requestBodyElement = $(requestBodyId);
        const inputElement = $(inputElementId);

        presentElement.prop('checked', par.valuePresent || false);
        requestBodyElement.prop('checked', par.requestBody || false);

        const disabled = !(par.valuePresent || par.requestBody);
        inputElement.prop('disabled', disabled);
        inputElement.prop('value', disabled ? '' : (par.value || ''));
    }

    /**
     * Rebuilds the scope lines and updates checkbox states from this.pars without rebinding the existing event
     * handlers.
     */
    refreshScopeValues() {
        const scope = this.pars.scope;
        this.renderScopeLine(this.scopeLines()[0]);
        $('#oidc-request-scope-present').prop('checked', scope.valuePresent || false);
        $('#oidc-request-scope-request-body').prop('checked', scope.requestBody || false);
        this.updateScopeBodyLine();
    }

    /**
     * Rebuilds the ACR values list UI and updates checkbox states from this.pars.acrValues
     * without rebinding the existing event handlers.
     */
    refreshAcrValues() {
        const acr = this.pars.acrValues;
        const oidcRequestAcrList = $('#oidc-request-acr-list');
        const oidcRequestAcrAddDiv = $('#oidc-request-acr-drop-div');
        const oidcRequestAcrCheckbox = $('#oidc-request-acr-present');
        const oidcRequestAcrRequestBodyCheckbox = $('#oidc-request-acr-request-body');

        const assignedUris = acr && acr.value
            ? acr.value.split(' ').filter(u => u.trim() !== '')
            : [];

        oidcRequestAcrList.empty();
        for (const uri of assignedUris) {
            OIDCAuthnRequest.addSelectedAcrValue(oidcRequestAcrList, uri);
        }
        if (assignedUris.length === 0) {
            oidcRequestAcrList.append($('<li>')
                .text("-- No URIs assigned --")
                .addClass('list-group-item d-flex justify-content-between align-items-center'));
        }

        oidcRequestAcrAddDiv.find('a[data-acr-attr]').removeClass('disabled');
        for (const uri of assignedUris) {
            oidcRequestAcrAddDiv.find('a[data-acr-attr="' + uri + '"]').addClass('disabled');
        }

        oidcRequestAcrCheckbox.prop('checked', acr ? (acr.valuePresent || false) : false);
        oidcRequestAcrRequestBodyCheckbox.prop('checked', acr ? (acr.requestBody || false) : false);
    }

    /**
     * Helper: rebuild language message rows in a messages div without rebinding handlers.
     * Removes existing rows (identified by label[data-langcode]), then adds new ones.
     * @param messagesDiv the jQuery div to populate
     * @param messagesObj e.g. { "message#sv": "text", "message#en": "text" }
     * @param sig true if this is a sign message (passed to createUserMessageDiv)
     */
    refreshMessageRows(messagesDiv, messagesObj, sig) {
        messagesDiv.find('label[data-langcode]').closest('.row').remove();
        const messages = messagesObj || {};
        for (const lang of AuthnRequest.UM_POSSIBLE_LANGUAGES) {
            const key = OIDCAuthnRequest.messageKey(lang.code);
            if (messages[key] !== undefined && messages[key] !== null) {
                const msgDiv = this.createUserMessageDiv(
                    { lang_code: lang.code, language: lang.text, message: messages[key] },
                    sig
                );
                if (msgDiv) {
                    messagesDiv.append(msgDiv);
                }
            }
        }
    }

    /**
     * Refreshes the user message UI from this.pars.userMessage without rebinding event handlers.
     */
    refreshUserMessage() {
        const um = this.pars.userMessage;
        $('#oidc-request-um-present').prop('checked', um.valuePresent || false);
        $('#oidc-request-um-request-body').prop('checked', um.requestBody || false);
        $('#oidc-request-um-b64').prop('checked', um.b64Encode || false);
        $('#oidc-request-um-div').toggle(!!(um.valuePresent || um.requestBody));
        $('#oidc-request-um-mimetype-select').val(um.mime_type || '');
        this.refreshMessageRows($('#oidc-request-um-messages-div'), um, false);
    }

    /**
     * Refreshes the advanced options UI from this.pars.advanced without rebinding event handlers.
     */
    refreshAdvanced() {
        const adv = this.pars.advanced;

        if (adv.moduleEnabled !== undefined) {
            adv.moduleEnabled ? $('#oidc-advanced-authn-request').show() : $('#oidc-advanced-authn-request').hide();
            $('#oidc-advanced-authn-options')
                .text((adv.moduleEnabled ? 'Hide ' : 'Display ') + 'advanced options');
        }

        // Module selectors: responseType, prompt, codeChallengeMethod
        for (const [field, sel, rbSel, presentSel] of [
            ['responseType',        '#oidc-request-responsetype-select',           '#oidc-request-responsetype-request-body',        '#oidc-request-responsetype-present'],
            ['prompt',              '#oidc-request-prompt-select',                 '#oidc-request-prompt-request-body',              '#oidc-request-prompt-present'],
            ['codeChallengeMethod', '#oidc-request-code_challenge_method-select',  '#oidc-request-code_challenge_method-request-body','#oidc-request-code_challenge_method-present'],
        ]) {
            if (adv[field] !== undefined) {
                if (adv[field].value      !== undefined) $(sel).val(adv[field].value);
                if (adv[field].requestBody  !== undefined) $(rbSel).prop('checked', adv[field].requestBody);
                if (adv[field].valuePresent !== undefined) $(presentSel).prop('checked', adv[field].valuePresent);
            }
        }

        // loginHint: user-editable nested field
        if (adv.loginHint !== undefined) {
            const lh = adv.loginHint;
            const disabled = !(lh.valuePresent || lh.requestBody);
            $('#oidc-request-login_hint-present').prop('checked', lh.valuePresent || false);
            $('#oidc-request-login_hint-request-body').prop('checked', lh.requestBody || false);
            $('#oidc-request-login_hint-input').prop('disabled', disabled).prop('value', disabled ? '' : (lh.value || ''));
        }

        // Server-generated fields: state, nonce, codeChallenge (value stays disabled until Modify)
        for (const [field, inputSel, rbSel, presentSel] of [
            ['state',         '#oidc-request-state-input',          '#oidc-request-state-request-body',          '#oidc-request-state-present'],
            ['nonce',         '#oidc-request-nonce-input',          '#oidc-request-nonce-request-body',          '#oidc-request-nonce-present'],
            ['codeChallenge', '#oidc-request-code_challenge-input', '#oidc-request-code_challenge-request-body', '#oidc-request-code_challenge-present'],
        ]) {
            if (adv[field] !== undefined) {
                const f = adv[field];
                if (f.value       !== undefined) $(inputSel).prop('value', f.value);
                if (f.requestBody  !== undefined) $(rbSel).prop('checked', f.requestBody);
                if (f.valuePresent !== undefined) $(presentSel).prop('checked', f.valuePresent);
            }
        }
    }

    /**
     * Refreshes the request object options UI from this.pars.requestObject without rebinding event handlers.
     */
    refreshRequestObject() {
        const ro = this.pars.requestObject;

        if (ro.moduleEnabled !== undefined) {
            $('#oidc-advanced-request-object-options').prop('checked', ro.moduleEnabled);
            ro.moduleEnabled ? $('#oidc-request-options').show() : $('#oidc-request-options').hide();
        }
        if (ro.signRequest   !== undefined) $('#oidc-request-sign-request-body').prop('checked', ro.signRequest);
        if (ro.encryptRequest !== undefined) $('#oidc-request-encrypt-request-body').prop('checked', ro.encryptRequest);

        // issuer and audience are server-generated (remain disabled until Modify is clicked)
        for (const [field, inputSel, rbSel, presentSel] of [
            ['issuer',   '#oidc-request-issuer-input', '#oidc-request-issuer-request-body', '#oidc-request-issuer-present'],
            ['audience', '#oidc-request-aud-input',    '#oidc-request-aud-request-body',    '#oidc-request-aud-present'],
        ]) {
            if (ro[field] !== undefined) {
                const f = ro[field];
                if (f.value       !== undefined) $(inputSel).prop('value', f.value);
                if (f.requestBody  !== undefined) $(rbSel).prop('checked', f.requestBody);
                if (f.valuePresent !== undefined) $(presentSel).prop('checked', f.valuePresent);
            }
        }
    }

    /**
     * Refreshes the keys UI from this.pars.keys without rebinding event handlers.
     */
    refreshKeys() {
        const keys = this.pars.keys;
        if (keys.moduleEnabled !== undefined) {
            $('#oidc-advanced-keys-request-check').prop('checked', keys.moduleEnabled);
            keys.moduleEnabled ? $('#oidc-advanced-keys-request').show() : $('#oidc-advanced-keys-request').hide();
        }
        if (keys.signKey !== undefined) $('#oidc-request-advanced-signkey-select').val(keys.signKey);
        if (keys.encKey  !== undefined) $('#oidc-request-advanced-enckey-select').val(keys.encKey);
    }

    /**
     * Refreshes the claims UI from this.pars.claims and this.pars.claimInRequestBody.
     * Clears and rebuilds claim rows, then calls computeClaims() to sync the textarea.
     */
    refreshClaims() {
        // Clear existing claim rows, keeping the hidden template row
        $('#oidc-id-claims-table').children().not('[id*="template"]').remove();

        const claims = this.pars.claims || {};

        // Merge id_token and userinfo entries into a single map keyed by claim name
        const claimMap = {};
        for (const location of ['id_token', 'userinfo']) {
            for (const [name, spec] of Object.entries(claims[location] || {})) {
                if (!claimMap[name]) {
                    claimMap[name] = { id_token: false, userinfo: false, essential: false, withValue: false, value: '' };
                }
                claimMap[name][location] = true;
                if (spec && spec.essential) {
                    claimMap[name].essential = true;
                } else if (spec && spec.value !== undefined) {
                    claimMap[name].withValue = true;
                    claimMap[name].value = String(spec.value);
                } else if (spec && spec.values !== undefined) {
                    claimMap[name].withValue = true;
                    claimMap[name].value = spec.values.join(',');
                }
            }
        }

        for (const [claimName, s] of Object.entries(claimMap)) {
            // Trigger add button to create a properly wired row
            $('#oidc-request-claims-id-add-button').trigger('click');
            const index = $('#oidc-id-claims-table').children().length - 1;

            // Set claim name and trigger change so computeClaims picks it up
            this.getClaimElement(index, this.claimIdentifiers["id"]["key-input"]).val(claimName).trigger('change');

            // Set location checkboxes (prop only; computeClaims called at the end)
            this.getClaimElement(index, this.claimIdentifiers["id"]["id-token-checkbox"]).prop('checked', s.id_token);
            this.getClaimElement(index, this.claimIdentifiers["id"]["userinfo-checkbox"]).prop('checked', s.userinfo);

            if (s.essential) {
                this.getClaimElement(index, this.claimIdentifiers["id"]["essential-checkbox"]).prop('checked', true);
            } else if (s.withValue) {
                const valueCheckbox = this.getClaimElement(index, this.claimIdentifiers["id"]["value-checkbox"]);
                const valueColumn   = this.getClaimElement(index, this.claimIdentifiers["id"]["value-column"]);
                const valueInput    = this.getClaimElement(index, this.claimIdentifiers["id"]["value-input"]);
                valueCheckbox.prop('checked', true);
                valueColumn.prop('disabled', false);
                valueInput.val(s.value).trigger('change');
            }
        }

        // Ensure claims are flagged as present so computeClaims writes them
        if (Object.keys(claimMap).length > 0) {
            this.switchOnClaims();
        }

        if (this.pars.claimInRequestBody !== undefined) {
            $('#oidc-request-claims-request-body').prop('checked', this.pars.claimInRequestBody);
        }

        this.computeClaims();
    }

    /**
     * Refreshes the sign message UI from this.pars.signMessage without rebinding event handlers.
     * @param applyScopeRule true to set the "TBS Data" box from the scope if the area goes from hidden to shown
     */
    refreshSignMessage(applyScopeRule = false) {
        const sig = this.pars.signMessage;

        $('#oidc-request-sig-present').prop('checked', sig.valuePresent || false);
        $('#oidc-request-sig-request-body').prop('checked', sig.requestBody || false);
        $('#oidc-request-sig-b64').prop('checked', sig.b64Encode || false);
        $('#oidc-request-sig-mimetype-select').val(this.signMessageObject().mime_type || '');

        const includeTbsData = sig.includeTbsData !== false;
        $('#oidc-request-tbs-include').prop('checked', includeTbsData);
        $('#oidc-request-tbs-textarea').prop('value', sig.tbsData || '').prop('disabled', !includeTbsData);

        const signJwt = sig.signJwt !== false;
        $('#oidc-request-sig-jwt-sign').prop('checked', signJwt);
        $('#oidc-request-sig-jwt-signkey-select').val(sig.signKey).prop('disabled', !signJwt);
        $('#oidc-request-sig-jwt-encrypt').prop('checked', sig.encryptJwt || false);

        this.updateSignMessageView(applyScopeRule);
        this.refreshMessageRows($('#oidc-request-sig-messages-div'), sig.signMessage, true);
    }

}
