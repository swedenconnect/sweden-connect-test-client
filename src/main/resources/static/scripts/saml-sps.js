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

function displaySamlSps() {
  $.ajax({
    url: './saml/sp/info',
    type: 'GET',
    success: function(info) {
      let listDiv = $('#saml-sp-list');
      listDiv.empty();
      for (let sp of info) {
        let spDiv = $('<div>');
        spDiv.append($('<h4>', {
          text: sp.entity_id
        }));
        let table = $('<table>', {
          class: 'table table-hover'
        }).append($('<tbody>')
            .append($('<tr>')
                .append($('<th>', {
                  scope: 'row',
                  text: "Description"
                }))
                .append($('<td>', {
                  text: sp.description
                })))
            .append($('<tr>')
                .append($('<th>', {
                  scope: 'row',
                  text: "Metadata URL"
                }))
                .append($('<td>')
                    .append($('<a>', {
                      href: sp.metadata_url,
                      text: sp.metadata_url,
                      target: '_blank',
                      rel: 'noopener'
                    }))
                    .append($('<span>', {
                      class: 'bi bi-box-arrow-up-right',
                      style: 'margin-left: 0.25rem;'
                    }))
                )
            ));
        spDiv.append(table);
        listDiv.append(spDiv);
      }
    },
    error: function(error) {
      console.error("Failed to get SP info: " + JSON.stringify(error));
      $('#saml-sp-list').empty();
    }
  });
}
