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
}

function displaySpOptions(spInfo) {
  const selectedSp = samlState.getSelectedSp();
  let spSelect = $('#saml-sp-select');
  let spInfoDiv = $('#sp-info');
  spInfoDiv.hide();
  if (spSelect.find('option').length === 0) {
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
}

function onSelectedSp(entityId) {
  if (entityId === "none") {
    $('#sp-info').hide();
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
}

$(document).ready(function() {

  $('#saml-sp-select').change(function() {
    let selectedSp = $(this).val();
    onSelectedSp(selectedSp);
  });

})
