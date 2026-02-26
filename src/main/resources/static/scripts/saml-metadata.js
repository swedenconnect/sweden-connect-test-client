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

// Gets the SAML federation info and displays it
//
function displayFederationInfo() {
  $.ajax({
    url: buildUrl('/saml/federation/info'),
    type: 'GET',
    success: function(info) {
      $('#saml-metadata-description').text(info.description);
      $('#saml-metadata-view-metadata').show();
      $('#saml-metadata-last-update').text(info.last_update);
    },
    error: function(error) {
      console.error("Failed to get federation info: " + JSON.stringify(error));
      $('#saml-metadata-description').empty();
      $('#saml-metadata-view-metadata').hide();
      $('#saml-metadata-last-update').empty();
    }
  });
}

$(document).ready(function() {

  $('#saml-metadata-view-metadata button').click(function() {
    //$('#xml-viewer .modal-title').text(getUIMessageText('ui.saml.xml.metadata.all'));

    $.ajax({
      url: buildUrl('/saml/federation/metadata'),
      type: 'GET',
      success: function(data) {
        codeViewer.displayXml("SAML Federation Metadata", data.metadata);
        //$('#xml-viewer .language-xml').text(data.metadata);
      },
      error: function(error) {
        console.error("Failed to get metadata: " + JSON.stringify(error));
      }
    });
    //$('#xml-viewer .modal').modal('show');
  });

})
