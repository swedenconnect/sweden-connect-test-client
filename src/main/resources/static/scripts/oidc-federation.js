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

class OidcFederation {

  constructor() {
    this.info = null;

    $('#oidf-refresh-button').off('click').on('click', () => this.refresh());
    $('#oidf-list-button').off('click').on('click', () => this.listSubordinates());
  }

  display() {
    this.loadInfo();
  }

  loadInfo() {
    $.ajax({
      url: buildUrl('/oidc/federation/info'),
      type: 'GET',
      success: (info) => this.setInfo(info),
      error: (error) => {
        console.error("Failed to get federation info: " + JSON.stringify(error));
        OidcFederation.displayError("Failed to get federation information");
      }
    });
  }

  refresh() {
    const button = $('#oidf-refresh-button');
    button.prop('disabled', true);
    $.ajax({
      url: buildUrl('/oidc/federation/refresh'),
      type: 'POST',
      success: (info) => {
        button.prop('disabled', false);
        this.setInfo(info);
      },
      error: (error) => {
        button.prop('disabled', false);
        console.error("Failed to refresh federation: " + JSON.stringify(error));
        OidcFederation.displayError("Failed to refresh the federation");
      }
    });
  }

  listSubordinates() {
    const authority = $('#oidf-authority-select').val();
    const entityType = $('#oidf-entity-type-select').val();

    let url = buildUrl('/oidc/federation/subordinates') + '?authority=' + encodeURIComponent(authority);
    if (entityType) {
      url = url + '&entity_type=' + encodeURIComponent(entityType);
    }

    const tbody = $('#oidf-subordinates-tbody');
    tbody.empty();
    tbody.append($('<tr>').append($('<td>', { colspan: 2, text: 'Listing subordinates ...' })));

    $.ajax({
      url: url,
      type: 'GET',
      success: (listing) => this.setSubordinates(listing),
      error: (error) => {
        console.error("Failed to list subordinates: " + JSON.stringify(error));
        tbody.empty();
        OidcFederation.displayError(OidcFederation.errorText(error, "Failed to list subordinates"));
      }
    });
  }

  resolve(entityId) {
    const url = buildUrl('/oidc/federation/resolve')
        + '?entity_id=' + encodeURIComponent(entityId)
        + '&trust_anchor=' + encodeURIComponent(OidcFederation.selectedTrustAnchor());

    $.ajax({
      url: url,
      type: 'POST',
      success: (resolved) => {
        this.loadInfo();
        codeViewer.displayJson("Resolved metadata for " + entityId, resolved.metadata);
      },
      error: (error) => {
        console.error("Failed to resolve: " + JSON.stringify(error));
        OidcFederation.displayError(OidcFederation.errorText(error, "Failed to resolve " + entityId));
      }
    });
  }

  showEntityConfiguration(entityId) {
    const url = buildUrl('/oidc/federation/entity-configuration')
        + '?entity_id=' + encodeURIComponent(entityId);

    $.ajax({
      url: url,
      type: 'GET',
      success: (ec) => codeViewer.displayJson("Entity configuration for " + entityId, ec.claims),
      error: (error) => {
        console.error("Failed to get entity configuration: " + JSON.stringify(error));
        OidcFederation.displayError(
            OidcFederation.errorText(error, "Failed to get the entity configuration for " + entityId));
      }
    });
  }

  /**
   * Builds the trust mark cell of the entity table - one badge per trust mark, where a trust mark that could not
   * be obtained (and therefore is not published) is marked as such, with the reason as its tooltip.
   */
  static trustMarkCell(trustMarks) {
    const cell = $('<td>', { class: 'oidf-trust-marks' });
    if (!trustMarks || trustMarks.length === 0) {
      return cell.append($('<span>', { class: 'text-muted', text: '-' }));
    }
    for (let trustMark of trustMarks) {
      cell.append($('<span>', {
        class: 'badge me-1 ' + (trustMark.published ? 'bg-success' : 'bg-danger'),
        text: trustMark.trust_mark_type,
        title: trustMark.published
            ? 'Issued by ' + trustMark.issuer + (trustMark.expires_at ? ', expires ' + trustMark.expires_at : '')
            : (trustMark.error || 'The trust mark could not be obtained')
      }));
    }
    return cell;
  }

  setInfo(info) {
    this.info = info;

    // Our own entities
    const entityTbody = $('#oidf-entities-tbody');
    entityTbody.empty();
    for (let entity of (info.entities || [])) {
      entityTbody.append($('<tr>')
          .append($('<td>', { text: entity.entity_id }))
          .append($('<td>', { text: entity.description || '' }))
          .append($('<td>')
              .append($('<a>', {
                href: entity.entity_configuration_url,
                text: entity.entity_configuration_url,
                target: '_blank',
                rel: 'noopener'
              })))
          .append(OidcFederation.trustMarkCell(entity.trust_marks))
          .append($('<td>')
              .append($('<button>', {
                type: 'button',
                class: 'btn btn-sm btn-outline-primary',
                text: 'View'
              }).on('click', () => this.showEntityConfiguration(entity.entity_id)))));
    }

    // The authorities that we may list subordinates of - the configured listing sources first (these are the
    // interesting ones), and then the trust anchors themselves.
    const authoritySelect = $('#oidf-authority-select');
    const currentAuthority = authoritySelect.val();
    authoritySelect.empty();

    const sources = info.listing_sources || [];
    const trustAnchors = info.trust_anchors || [];
    const sourceIds = sources.map(s => s.entity_id);

    if (sources.length > 0) {
      const sourceGroup = $('<optgroup>', { label: 'Configured listing sources' });
      for (let source of sources) {
        sourceGroup.append($('<option>', {
          value: source.entity_id,
          text: source.entity_id,
          'data-trust-anchor': source.trust_anchor
        }));
      }
      authoritySelect.append(sourceGroup);
    }

    const remainingAnchors = trustAnchors.filter(ta => !sourceIds.includes(ta));
    if (remainingAnchors.length > 0) {
      const anchorGroup = $('<optgroup>', { label: 'Trust anchors' });
      for (let ta of remainingAnchors) {
        anchorGroup.append($('<option>', { value: ta, text: ta, 'data-trust-anchor': ta }));
      }
      authoritySelect.append(anchorGroup);
    }

    if (currentAuthority && authoritySelect.find('option[value="' + currentAuthority + '"]').length > 0) {
      authoritySelect.val(currentAuthority);
    }

    $('#oidf-last-refresh').text(info.last_refresh ? info.last_refresh : 'Not yet refreshed');

    // Errors
    const errorDiv = $('#oidf-errors');
    const errorList = $('#oidf-errors-list');
    errorList.empty();
    if (info.errors && info.errors.length > 0) {
      for (let error of info.errors) {
        errorList.append($('<li>', { text: error }));
      }
      errorDiv.removeClass('hide').show();
    }
    else {
      errorDiv.hide();
    }

    this.setProviders(info.providers || []);
  }

  setProviders(providers) {
    const tbody = $('#oidf-providers-tbody');
    tbody.empty();
    if (providers.length === 0) {
      tbody.append($('<tr>').append($('<td>', {
        colspan: 4,
        text: 'No OpenID Providers have been configured from the federation'
      })));
      return;
    }
    for (let op of providers) {
      tbody.append($('<tr>')
          .append($('<td>', { text: op.entity_id }))
          .append($('<td>', { text: op.display_name || '' }))
          .append($('<td>', { text: op.trust_anchor || '' }))
          .append($('<td>')
              .append($('<button>', {
                type: 'button',
                class: 'btn btn-sm btn-outline-primary',
                text: 'Metadata'
              }).on('click', () => OidcFederation.showOpMetadata(op.entity_id)))));
    }
  }

  setSubordinates(listing) {
    const tbody = $('#oidf-subordinates-tbody');
    tbody.empty();
    const subordinates = listing.subordinates || [];
    if (subordinates.length === 0) {
      tbody.append($('<tr>').append($('<td>', { colspan: 2, text: 'No subordinates found' })));
      return;
    }
    for (let entityId of subordinates) {
      tbody.append($('<tr>')
          .append($('<td>', { text: entityId }))
          .append($('<td>')
              .append($('<button>', {
                type: 'button',
                class: 'btn btn-sm btn-outline-primary',
                text: 'Entity configuration',
                style: 'margin-right: 0.25rem;'
              }).on('click', () => this.showEntityConfiguration(entityId)))
              .append($('<button>', {
                type: 'button',
                class: 'btn btn-sm btn-primary',
                text: 'Resolve and add'
              }).on('click', () => this.resolve(entityId)))));
    }
  }

  /**
   * The selected authority may be an intermediate - resolution is always made against the trust anchor that the
   * authority was configured under.
   */
  static selectedTrustAnchor() {
    const select = $('#oidf-authority-select');
    const option = select.find('option:selected');
    return option.data('trust-anchor') || select.val();
  }

  static showOpMetadata(entityId) {
    $.ajax({
      url: buildUrl('/oidc/op/metadata?op=' + encodeURIComponent(entityId)),
      type: 'GET',
      success: (metadata) => codeViewer.displayJson("Metadata for " + entityId, metadata),
      error: (error) => {
        console.error("Failed to get OP metadata: " + JSON.stringify(error));
        OidcFederation.displayError("Failed to get the metadata for " + entityId);
      }
    });
  }

  static errorText(error, fallback) {
    if (error && error.responseJSON && error.responseJSON.message) {
      return error.responseJSON.message;
    }
    return fallback;
  }

  static displayError(message) {
    $('#error-modal-contents').html($('<p>').text(message));
    $('#error-modal').modal('show');
  }

}
