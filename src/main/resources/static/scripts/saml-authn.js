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

const PRINCIPAL_ATTRIBUTES = [
  {
    friendlyName: "personalIdentityNumber", name: "urn:oid:1.2.752.29.4.13",
    info: "Enter personal identity number (12 digits, no hyphen)"
  },
  {friendlyName: "prid", name: "urn:oid:1.2.752.201.3.4", info: "Enter provisional ID"},
  {friendlyName: "eidasPersonIdentifier", name: "urn:oid:1.2.752.201.3.7", info: "Enter eIDAS person identifier"},
  {
    friendlyName: "mappedPersonalIdentityNumber", name: "urn:oid:1.2.752.201.3.16",
    info: "Enter personal identity number (12 digits, no hyphen)"
  },
  {friendlyName: "c - country", name: "urn:oid:2.5.4.6", info: "Enter country code (2 letters)"},
  {friendlyName: "dateOfBirth", name: "urn:oid:1.3.6.1.5.5.7.9.1", info: "Enter date of birth (YYYY-MM-DD)"},
  {friendlyName: "sn - surname", name: "urn:oid:2.5.4.4", info: "Enter surname"},
  {friendlyName: "givenName", name: "urn:oid:2.5.4.42", info: "Enter given name"}
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
    $('html, body').animate({scrollTop: pos}, 'slow');

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

function populateAuthnRequestParameters(template) {
  // Request bindings
  let samlRequestBindingSelect = $('#saml-request-binding-select');
  for (let b of template.possible_request_bindings) {
    let rb = b === template.request_binding;
    samlRequestBindingSelect.append(new Option(b, b, false, rb));
  }

  // ForceAuthn
  if (template.force_authn === true) {
    $('#saml-request-forceauthn-true').prop('checked', true);
  }
  else if (template.force_authn === false) {
    $('#saml-request-forceauthn-false').prop('checked', true);
  }
  else {
    $('#saml-request-forceauthn-exclude').prop('checked', true);
  }

  // IsPassive
  if (template.is_passive === true) {
    $('#saml-request-ispassive-true').prop('checked', true);
  }
  else if (template.is_passive === false) {
    $('#saml-request-ispassive-false').prop('checked', true);
  }
  else {
    $('#saml-request-ispassive-exclude').prop('checked', true);
  }

  // Destination
  $('#saml-request-destination').val(template.destination);

  // Issuer
  $('#saml-request-issuer').val(template.issuer);
  $('#saml-request-issuer-present').prop('checked', true);

  // NameID Policy
  if (template.name_id_policy) {
    $('#saml-request-nip-present').prop('checked', true);
    if (template.name_id_policy.format) {
      $('#saml-request-nip-format').val(template.name_id_policy.format);
    }
    else {
      $('#saml-request-nip-format').val('exclude');
    }
    if (template.name_id_policy.allow_create === true) {
      $('#saml-request-nip-ac-true').prop('checked', true);
    }
    else if (template.name_id_policy.allow_create === false) {
      $('#saml-request-nip-ac-false').prop('checked', true);
    }
    else {
      $('#saml-request-nip-ac-exclude').prop('checked', true);
    }
    if (template.name_id_policy.sp_name_qualifier) {
      $('#saml-request-nip-spnq').val(template.name_id_policy.sp_name_qualifier);
    }
  }
  else {
    $('#saml-request-nip-present').prop('checked', false);
    $('#saml-request-nip-div').hide();
  }

  // Requested Authentication Context Class Ref URIs
  let samlRequestRacList = $('#saml-request-rac-list');
  samlRequestRacList.empty();
  if (template.requested_authn_context_class_uris) {
    for (let b of template.requested_authn_context_class_uris) {
      addSelectedAuthnContextClassUri(samlRequestRacList, b);
    }
  }
  let selectedUris = getSelectedAuthnContextClassUris();
  if (selectedUris.length === 0) {
    samlRequestRacList.append($('<li>')
        .text("-- No URIs assigned --")
        .addClass('list-group-item d-flex justify-content-between align-items-center'));
  }
  let samlRequestRacSelect = $('#saml-request-rac-select');
  samlRequestRacSelect.empty();
  samlRequestRacSelect.append(new Option("Add URI ...", "add", true, true));
  for (let uri of AUTHN_CONTEXT_CLASS_REF_URIS) {
    let opt = new Option(uri, uri);
    opt.disabled = selectedUris.includes(uri);
    samlRequestRacSelect.append(opt);
  }
  samlRequestRacSelect.append(new Option("Enter other URI ...", "other", false, false));

  if (template.requested_authn_context_class_uris) {
    $('#saml-request-rac-present').prop('checked', true);
    $('#saml-request-rac-div').show();
  }
  else {
    $('#saml-request-rac-present').prop('checked', false);
    $('#saml-request-rac-div').hide();
  }

  // Assertion Consumer Service URL
  let acsSelect = $('#saml-request-acs-select');
  for (let acs of template.possible_assertion_consumer_service_urls) {
    acsSelect.append(new Option(acs, acs));
  }
  acsSelect.append(new Option("Enter other URL ...", "add", false, false));
  acsSelect.append(new Option("-- Not assigned --", "exclude", true, true));
  if (template.assertion_consumer_service_url) {
    let opt = acsSelect.find('option[value="' + template.assertion_consumer_service_url + '"]');
    opt.prop('selected', true);
  }

  // Principal Selection extension
  let pseSelect = $('#saml-request-pse-select');
  pseSelect.append(new Option("Add attribute ...", "add", true, true));
  for (let attr of PRINCIPAL_ATTRIBUTES) {
    pseSelect.append(new Option(attr.name + ' (' + attr.friendlyName + ')', attr.name, false, false));
  }
  $('#saml-request-pse-attrs-div').hide();
  $('#saml-request-pse-attrs').empty();
  $('#saml-request-pse-present').prop('checked', false);
  $('#saml-request-pse-div').hide();
}

function addSelectedAuthnContextClassUri(list, uri) {
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

function getSelectedAuthnContextClassUris() {
  return $('#saml-request-rac-list').find('li span').map(function() {
    return $(this).text();
  }).get();
}

function addPrincipalSelectionAttribute(attr) {
  let attrObj = PRINCIPAL_ATTRIBUTES.find(a => a.name === attr);
  if (!attrObj) {
    return;
  }

  let attrsDiv = $('#saml-request-pse-attrs');
  let ad = $('<div>');
  if (attrsDiv.children().length > 0) {
    ad.addClass("mt-4");
  }
  const inputId = generateRandomId();
  const buttonId = generateRandomId();
  ad.append($('<label>', {
    for: inputId,
    text: attrObj.friendlyName + ' (' + attrObj.name + ')'
  }));

  let inputDiv = $('<div>', {
    class: 'input-group mt-2'
  });
  inputDiv.append($('<input>', {
    id: inputId,
    type: 'text',
    placeholder: attrObj.info,
    class: 'form-control',
    'aria-describedby': buttonId
  }))
      .append($('<div>', {class: 'd-flex align-items-center position-absolute top-0 end-0 h-100 pe-3'})
          .append($('<button>', {
            id: buttonId,
            type: 'button',
            class: 'btn btn-close'
          })));
  ad.append(inputDiv);
  attrsDiv.append(ad);
}


$(document).ready(function() {

  $('#menu-saml').click(function(event) {
    onNavbarClicked(event, 'saml');
    displaySpAndIdpOptions();
  });

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
        $('#xml-viewer .modal-title').text(entityId);
        $('#xml-viewer .language-xml').text(idp.metadata);
        $('#xml-viewer .modal').modal('show');
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
        populateAuthnRequestParameters(response);
        samlState.buildAuthnState = true;
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

  $('#saml-request-issueinstant-button').click(function() {
    $('#saml-request-issueinstant').val(new Date().toISOString());
    $(this).hide();
  });

  $('#saml-request-issuer-present').change(function() {
    $('#saml-request-issuer-row').toggle(this.checked);
  });

  $('#saml-request-nip-present').change(function() {
    $('#saml-request-nip-div').toggle(this.checked);
  });

  $('#saml-request-rac-present').change(function() {
    $('#saml-request-rac-div').toggle(this.checked);
  });

  $('#saml-request-rac-list').on('click', 'button.btn-close', function() {
    let ul = $(this).closest('ul');
    $(this).closest('li').remove();

    let uri = $(this).closest('li').find('span').text();
    let opt = $("#saml-request-rac-select option[value='" + uri + "']");
    if (opt !== 0) {
      opt.prop('disabled', false);
    }

    if (ul.children('li').length === 0) {
      ul.append($('<li>')
          .text("-- No URIs assigned --")
          .addClass('list-group-item d-flex justify-content-between align-items-center'));
    }
  });

  $('#saml-request-rac-select').change(function() {
    let selectedOption = $(this).find('option:selected');
    let samlRequestRacList = $('#saml-request-rac-list');

    if (selectedOption.val() === 'add') {
      $('#saml-request-rac-custom-div').hide();
    }
    else if (selectedOption.val() === 'other') {
      $('#saml-request-rac-custom-div').show();
    }
    else {
      $('#saml-request-rac-custom-div').hide();
      addSelectedAuthnContextClassUri(samlRequestRacList, selectedOption.val());
      selectedOption.prop('disabled', true);
      $(this).find("option[value='add']").prop('selected', true);
    }
  });

  $('#saml-request-rac-custom-button').click(function() {
    let samlRequestRacCustom = $('#saml-request-rac-custom');
    let uri = samlRequestRacCustom.val().trim();
    if (uri !== '') {
      addSelectedAuthnContextClassUri($('#saml-request-rac-list'), uri);
      samlRequestRacCustom.val('');
      $('#saml-request-rac-custom-div').hide();
      $("#saml-request-rac-select option[value='add']").prop('selected', true);
    }
  });

  $('#saml-request-acs-select').change(function() {
    let selectedOption = $(this).find('option:selected');

    if (selectedOption.val() === 'add') {
      $('#saml-request-acs-custom-div').show();
    }
    else {
      $('#saml-request-acs-custom-div').hide();
      $('#saml-request-acs-custom').val('');
    }
  });

  $('#saml-request-pse-present').change(function() {
    $('#saml-request-pse-div').toggle(this.checked);
  })

  $('#saml-request-pse-select').change(function() {
    let selectedOption = $(this).find('option:selected');
    if (selectedOption.val() === 'add') {
      return;
    }
    else {
      addPrincipalSelectionAttribute(selectedOption.val());
      $('#saml-request-pse-attrs-div').show();
      $("#saml-request-pse-select option[value='add']").prop('selected', true);
    }
  });

  $('#saml-request-pse-attrs').on('click', 'button.btn-close', function() {
    $(this).parent().parent().parent().remove();

    if ($('#saml-request-pse-attrs').children().length === 0) {
      $('#saml-request-pse-attrs-div').hide();
    }
  });

})
