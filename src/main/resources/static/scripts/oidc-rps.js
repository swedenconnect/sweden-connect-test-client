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

class OidcRelyingParties {

  display() {
    $.ajax({
      url: buildUrl('/oidc/rp/info'),
      type: 'GET',
      success: function(info) {
        OidcRelyingParties.setRpList(info);
      },
      error: function(error) {
        console.error("Failed to get RP info: " + JSON.stringify(error));
        OidcRelyingParties.setRpList([]);
      }
    });
  }

  static setRpList(info) {
    const rpList = $('#oidc-rp-list');
    rpList.empty();
    console.log(("SETTING INFO" + JSON.stringify(info)));
    for (let rp of info) {
      let rpDiv = $('<div>');
      rpDiv.append($('<h4>', {
        text: rp.entity_id
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
                text: rp.description
              })))
          .append($('<tr>')
              .append($('<th>', {
                scope: 'row',
                text: "Metadata URL"
              }))
              .append($('<td>')
                  .append($('<a>', {
                    href: rp.metadata_url,
                    text: rp.metadata_url,
                    target: '_blank',
                    rel: 'noopener'
                  }))
                  .append($('<span>', {
                    class: 'bi bi-box-arrow-up-right',
                    style: 'margin-left: 0.25rem;'
                  })))));
      rpDiv.append(table);
      rpList.append(rpDiv);
    }
  }

}
