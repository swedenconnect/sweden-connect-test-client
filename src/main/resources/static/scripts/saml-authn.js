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

const AUTHN_CONTEXT_CLASS_REF_URIS = [
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

const NAME_ID_FORMATS = [
  "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
  "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
  "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
];

const PRINCIPAL_ATTRIBUTES = [
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

function displaySpAndIdpOptions() {
  if (samlState.spInfoCache) {
    displaySpOptions(samlState.spInfoCache);
  }
  else {
    $.ajax({
      url: '/saml/authn/info',
      type: 'GET',
      success: function(info) {
        samlState.spInfoCache = info.sps;
        samlState.idpInfoCache = info.idps;
        displaySpOptions(samlState.spInfoCache);
      },
      error: function(error) {
        console.error("Failed to get SP info: " + JSON.stringify(error));
        displaySpOptions([]);
      }
    });
  }
  if (samlState.idpInfoCache) {
    displayIdpOptions(samlState.idpInfoCache);
  }
  else {
    $.ajax({
      url: '/saml/authn/info',
      type: 'GET',
      success: function(info) {
        samlState.spInfoCache = info.sps;
        samlState.idpInfoCache = info.idps;
        displayIdpOptions(samlState.idpInfoCache);
      },
      error: function(error) {
        console.error("Failed to get IdP info: " + JSON.stringify(error));
        displayIdpOptions([]);
      }
    });
  }

  if (samlState.buildAuthnState) {
    $('#saml-build-authn').show();
    $('#saml-authn-next-button').prop('disabled', true);
  }
  else {
    $('#saml-build-authn').hide();
  }
}

function displaySpOptions(spInfo) {
  let spSelect = $('#saml-sp-select');
  if (spSelect.find('option').length === 0) {
    let spInfoDiv = $('#sp-info');
    const selectedSp = samlState.getSelectedSp();
    spInfoDiv.hide();
    spSelect.append(new Option("--- Select SP ---", "none", true, false));
    for (const sp of spInfo) {
      const isSelected = sp.entity_id === (selectedSp || "");
      spSelect.append(new Option(sp.entity_id, sp.entity_id, false, isSelected));
      if (isSelected) {
        $('#sp-description').text(sp.description);
        let spUrl = $('#sp-metadata-url');
        spUrl.attr('href', sp.metadata_url);
        spUrl.text(sp.metadata_url);
        $('#sp-view-metadata').attr('value', sp.entity_id);
        spInfoDiv.show();
      }
    }
  }
  updateSelectSpAndIdpState();
}

function onSelectedSp(entityId) {
  if (entityId === "none") {
    $('#sp-info').hide();
    samlState.setSelectedSp(null);
    samlState.buildAuthnState = false;
    $('#saml-build-authn').hide();
  }
  else {
    for (const sp of samlState.spInfoCache) {
      if (sp.entity_id === entityId) {
        $('#sp-description').text(sp.description);
        let spUrl = $('#sp-metadata-url');
        spUrl.attr('href', sp.metadata_url);
        spUrl.text(sp.metadata_url);
        $('#sp-view-metadata').attr('value', sp.entity_id);
        $('#sp-info').show();
        samlState.setSelectedSp(entityId);
        break;
      }
    }
  }
  updateSelectSpAndIdpState();
}

function displayIdpOptions(idpInfo) {
  let idpSelect = $('#saml-idp-select');
  if (idpSelect.find('option').length === 0) {
    let idpInfoDiv = $('#idp-info');
    const selectedIdp = samlState.getSelectedIdp();
    idpInfoDiv.hide();
    idpSelect.append(new Option("--- Select IdP ---", "none", true, false));
    for (const idp of idpInfo) {
      const isSelected = idp.entity_id === (selectedIdp || "");
      idpSelect.append(new Option(idp.entity_id, idp.entity_id, false, isSelected));
      if (isSelected) {
        $('#idp-displayname').text(idp.display_name);
        $('#idp-description').text(idp.description);
        $('#idp-view-metadata').attr('value', idp.entity_id);
        idpInfoDiv.show();
      }
    }
  }
  updateSelectSpAndIdpState();
}

function onSelectedIdp(entityId) {
  if (entityId === "none") {
    $('#idp-info').hide();
    samlState.setSelectedIdp(null);
    samlState.buildAuthnState = false;
    $('#saml-build-authn').hide();
  }
  else {
    for (const idp of samlState.idpInfoCache) {
      if (idp.entity_id === entityId) {
        $('#idp-displayname').text(idp.display_name);
        $('#idp-description').text(idp.description);
        $('#idp-view-metadata').attr('value', idp.entity_id);
        $('#idp-info').show();
        samlState.setSelectedIdp(entityId);
        break;
      }
    }
  }
  updateSelectSpAndIdpState();
}

function updateSelectSpAndIdpState() {
  let samlSpSelect = $('#saml-sp-select');
  let samlIdpSelect = $('#saml-idp-select');

  if (samlState.buildAuthnState) {
    samlSpSelect.prop('disabled', true);
    samlIdpSelect.prop('disabled', true);

    let samlBuildAuthnDiv = $('#saml-build-authn');
    samlBuildAuthnDiv.show();
    let pos = samlBuildAuthnDiv.offset().top;
    $('html, body').animate({ scrollTop: pos }, 'slow');

    $('#saml-authn-next-button').prop('disabled', true);

    return;
  }

  samlSpSelect.prop('disabled', false);
  samlIdpSelect.prop('disabled', false);

  if (samlState.getSelectedSp() == null || samlState.getSelectedIdp() == null) {
    $('#saml-authn-next-button').prop('disabled', true);
  }
  else {
    $('#saml-authn-next-button').prop('disabled', false);
  }
}

$(document).ready(function() {

  $('#saml-sp-select').change(function() {
    let selectedSp = $(this).val();
    onSelectedSp(selectedSp);
  });

  $('#saml-idp-select').change(function() {
    let selectedIdp = $(this).val();
    onSelectedIdp(selectedIdp);
  });

  $('#idp-view-metadata').click(function() {
    let entityId = $(this).val();
    for (const idp of samlState.idpInfoCache) {
      if (idp.entity_id === entityId) {
        codeViewer.displayXml(entityId, idp.metadata);
        break;
      }
    }
  });

  $('#sp-view-metadata').click(function() {
    let entityId = $(this).val();
    for (const sp of samlState.spInfoCache) {
      if (sp.entity_id === entityId) {
        codeViewer.displayXml(entityId, sp.metadata);
        break;
      }
    }
  });

  $('#saml-authn-next-button').click(function() {

    $.ajax({
      url: '/saml/authn/template',
      type: 'GET',
      data: {
        sp: samlState.getSelectedSp(),
        idp: samlState.getSelectedIdp()
      },
      success: function(response) {
        $('#saml-advanced-authn-request').hide();
        samlState.buildAuthnState = true;
        samlState.authnRequest = new AuthnRequest(response);
        updateSelectSpAndIdpState();
      },
      error: function(error) {
        console.error("Failed to generate authentication request template: " + JSON.stringify(error));
      }
    });

  });

  $('#saml-advanced-authn-request-button').click(function() {
    $('#saml-advanced-authn-request-button-div').hide();
    $('#saml-advanced-authn-request').show();
  });

  $('#saml-request-restart-button').click(function() {
    $('#saml-build-authn').hide();
    $('#saml-authn-next-button').prop('disabled', false);
    samlState.buildAuthnState = false;

    $('#saml-sp-select').prop('disabled', false);
    $('#saml-idp-select').prop('disabled', false);

    let mainDiv = $('#main-saml');
    let pos = mainDiv.offset().top;
    $('html, body').animate({ scrollTop: pos }, 'slow');
  });

  $('#saml-request-submit-button').click(function() {
    let authnRequestParameters = samlState.authnRequest.getAuthnRequestParameters();
    alert(JSON.stringify(authnRequestParameters));

    $.ajax({
      url: '/saml/authn/generate',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(authnRequestParameters),
      dataType: 'json',
      success: function(response) {
        alert(JSON.stringify(response));
      },
      error: function(error) {
        console.error("Failed to generate SAML AuthnRequest: " + JSON.stringify(error));
      }
    });

  });

})

/**
 * Represents the SAML AuthnRequest regarding the HTML elements that are displayed.
 */
class AuthnRequest {

  /**
   * Constructor that initializes all elements for the SAML AuthnRequest based on the supplied template.
   * @param template the AuthnRequest template received from the backend
   */
  constructor(template) {
    this.template = template;

    // Will hold the modified parameters
    this.pars = JSON.parse(JSON.stringify(template));

    this.initRequestBindings(this.template.request_binding, this.template.possible_request_bindings);
    this.initRelayState(this.template.relay_state);
    this.initSignatureOptions(this.template.signature_option);
    this.initForceAuthn(this.template.force_authn);
    this.initIsPassive(this.template.is_passive);
    this.initDestination(this.template.destination);
    this.initIssueInstant();
    this.initIssuer(this.template.issuer);
    this.initNameIdPolicy(this.template.name_id_policy);
    this.initRequestedAuthnContext(this.template.requested_authn_context);
    this.initAcs(this.template.assertion_consumer_service_url, this.template.possible_assertion_consumer_service_urls);
    this.initRequestedPrincipalSelection();
    this.initUserMessage(this.template.user_message_extension);
    this.initScoping();
    this.initSignMessage(this.template.idp, this.template.sign_message);
  }

  /**
   * Gets the AuthnRequest parameters that (may) have been modified by the user.
   * @returns {any} AuthnRequest parameters
   */
  getAuthnRequestParameters() {
    this.pars.request_binding = this.getRequestBinding();
    this.pars.relay_state = this.getRelayState();
    this.pars.signature_option = this.getSignatureOption();
    this.pars.force_authn = this.getForceAuthn();
    this.pars.is_passive = this.getIsPassive();
    this.pars.destination = this.getDestination();
    this.pars.isssue_instant = this.getIssueInstant();
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
    let samlRequestBindingSelect = $('#saml-request-binding-select');
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

  initDestination(dest) {
    $('#saml-request-destination').val(dest || '');
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
      issuerRow.toggle(issuerCheckbox.checked);
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

  /**
   * Initializes the NameID Policy element.
   * @param nip the NameID policy object
   */
  initNameIdPolicy(nip) {
    let nipCheckbox = $('#saml-request-nip-present');
    let nipFormatSelect = $('#saml-request-nip-format');
    let nipDiv = $('#saml-request-nip-div');

    for (let format of NAME_ID_FORMATS) {
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
      nipDiv.toggle(nipCheckbox.checked);
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
      policy.allow_create = AuthnRequest.getRadioButtonTrueFalseExclude("saml-request-nip-ac-true");
      policy.sp_name_qualifier = AuthnRequest.getValueFromInput($('#saml-request-nip-spnq'));
      return policy;
    }
    else {
      return null;
    }
  }

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
    for (let uri of AUTHN_CONTEXT_CLASS_REF_URIS) {
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
      samlRequestRacDiv.toggle(samlRequestRacCheckbox.checked);
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
    for (let attr of PRINCIPAL_ATTRIBUTES) {
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
      pseDiv.toggle(pseCheckbox.checked);
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
      umDiv.toggle(umCheckbox.checked);
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
      click: function(event) {
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
      scopingDiv.toggle(scopingCheckbox.checked);
    });
  }

  getScoping() {
    if ($('#saml-request-scoping-present').prop('checked')) {
      let scoping = {};
      scoping.requester_id = AuthnRequest.getValueFromInput($('#saml-request-scoping-requesterid'));
      scoping.idp_list = [];

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
      smDiv.toggle(smCheckbox.checked);
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
