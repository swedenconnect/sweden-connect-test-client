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

function onNavbarClicked(event, name) {
  if (event != null) {
    event.preventDefault();
  }
  $('.main-div').hide();
  $("#main-" + name).show();
}

function initPage() {
  $('.noscripthide').show();
  $('[data-bs-toggle="tooltip"]').tooltip();
  let feature = appState.getSelectedFeature();
  if (feature) {
    $("#menu-" + feature).trigger('click');
  }
  else {
    onNavbarClicked(null, 'home');
  }
}

function getUIMessageText(value) {
  let modifiedValue = value.replace(/\./g, '_');
  let message = ui_messages[modifiedValue] || '';
  message = message.replace(/^\/\*|"|\*\/$/g, '');
  return message;
}

function generateRandomId(prefix = 'id') {
  return prefix + '_' + Math.random().toString(36).slice(2, 11);
}

function getInputValue(id) {
  let value = $('#' + id).val().trim();
  return value === '' ? null : value;
}

function setRadioButtonTrueFalseExclude(radio, value) {
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

function getRadioButtonTrueFalseExclude(radio) {
  let val = $('input[name="' + radio + '"]:checked');
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

$(document).ready(function() {

  //
  // Navigation menu actions
  //
  $('#menu-home').click(function(event) {
    appState.setSelectedFeature('home');
    onNavbarClicked(event, 'home');
  });

  $('#menu-saml').click(function(event) {
    appState.setSelectedFeature('saml');
    onNavbarClicked(event, 'saml');
    displaySpAndIdpOptions();
  });

  $('#menu-oidc').click(function(event) {
    appState.setSelectedFeature('oidc');
    onNavbarClicked(event, 'oidc');
  });

  $('#menu-saml-clients').click(function(event) {
    appState.setSelectedFeature('saml-clients');
    onNavbarClicked(event, 'saml-clients');
    displaySamlSps();
  });

  $('#menu-saml-metadata').click(function(event) {
    appState.setSelectedFeature('saml-metadata');
    onNavbarClicked(event, 'saml-metadata');
    displayFederationInfo();
  });

  initPage();

});
