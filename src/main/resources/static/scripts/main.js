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
  onNavbarClicked(null, 'home');
}

function getUIMessageText(value) {
  let modifiedValue = value.replace(/\./g, '_');
  let message = ui_messages[modifiedValue] || '';
  message = message.replace(/^\/\*|"|\*\/$/g, '');
  return message;
}

$(document).ready(function() {

  initPage();

  //
  // Navigation menu actions
  //
  $('#menu-home').click(function(event) {
    onNavbarClicked(event, 'home');
  });

  $('#menu-saml').click(function(event) {
    onNavbarClicked(event, 'saml');
  });

  $('#menu-oidc').click(function(event) {
    onNavbarClicked(event, 'oidc');
  });

  $('#menu-saml-clients').click(function(event) {
    onNavbarClicked(event, 'saml-clients');
  });

  $('#menu-saml-metadata').click(function(event) {
    onNavbarClicked(event, 'saml-metadata');
    displayFederationInfo();
  });

});
