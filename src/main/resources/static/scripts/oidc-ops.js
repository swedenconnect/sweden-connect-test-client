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

class OidcProviders {

  display() {
    $.ajax({
      url: buildUrl('/oidc/op/info'),
      type: 'GET',
      success: function(info) {
        OidcProviders.setOpList(info);
      },
      error: function(error) {
        console.error("Failed to get OP info: " + JSON.stringify(error));
        OidcProviders.setOpList([]);
      }
    });
  }

  static setOpList(info) {
    const opList = $('#oidc-op-list');
    opList.empty();
    for (let op of info) {
      let opDiv = $('<div>');
      opDiv.append($('<h4>', {
        text: op.entity_id
      }));
      let tbody = $('<tbody>');
      tbody.append($('<tr>')
          .append($('<th>', { scope: 'row', text: "Source" }))
          .append($('<td>', {
            text: op.source === 'federation' ? "OpenID Federation" : "Statically configured"
          })));
      if (op.trust_anchor) {
        tbody.append($('<tr>')
            .append($('<th>', { scope: 'row', text: "Trust Anchor" }))
            .append($('<td>', { text: op.trust_anchor })));
      }
      if (op.display_name) {
        tbody.append($('<tr>')
            .append($('<th>', { scope: 'row', text: "Display Name" }))
            .append($('<td>', { text: op.display_name })));
      }
      if (op.description) {
        tbody.append($('<tr>')
            .append($('<th>', { scope: 'row', text: "Description" }))
            .append($('<td>', { text: op.description })));
      }
      tbody.append($('<tr>')
          .append($('<th>', {
            scope: 'row',
            text: op.source === 'federation' ? "Entity Configuration URL" : "Metadata URL"
          }))
          .append($('<td>')
              .append($('<a>', {
                href: op.metadata_url,
                text: op.metadata_url,
                target: '_blank',
                rel: 'noopener'
              }))
              .append($('<span>', {
                class: 'bi bi-box-arrow-up-right',
                style: 'margin-left: 0.25rem;'
              }))));
      opDiv.append($('<table>', { class: 'table table-hover' }).append(tbody));
      opList.append(opDiv);
    }
  }

}
