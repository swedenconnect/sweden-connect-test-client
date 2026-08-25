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

  /** How often the status view is updated from the server (the discovery itself runs on the server). */
  static POLL_INTERVAL_MS = 30000;

  constructor() {
    this.info = null;
    this.pollTimer = null;
  }

  /**
   * The providers are discovered and configured by the server without any user interaction - the view just polls
   * for the current status while it is displayed.
   */
  display() {
    this.loadInfo();
    if (!this.pollTimer) {
      this.pollTimer = setInterval(() => {
        if ($('#main-oidc-federation').is(':visible')) {
          this.loadInfo(true);
        }
      }, OidcFederation.POLL_INTERVAL_MS);
    }
  }

  /**
   * @param silent when polling, a failure is logged but does not raise an error dialog in the user's face
   */
  loadInfo(silent) {
    $.ajax({
      url: buildUrl('/oidc/federation/info'),
      type: 'GET',
      success: (info) => this.setInfo(info),
      error: (error) => {
        console.error("Failed to get federation info: " + JSON.stringify(error));
        if (!silent) {
          OidcFederation.displayError("Failed to get federation information");
        }
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

    $('#oidf-trust-anchors').text((info.trust_anchors && info.trust_anchors.length > 0)
        ? info.trust_anchors.join(', ')
        : '-');
    $('#oidf-last-refresh').text(info.last_refresh ? info.last_refresh : 'Not yet checked');
    $('#oidf-refresh-interval').text(info.refresh_interval
        ? ' (the federation is checked every ' + OidcFederation.duration(info.refresh_interval) + ')'
        : '');

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
        colspan: 5,
        text: 'No OpenID Providers have been configured from the federation'
      })));
      return;
    }
    for (let op of providers) {
      const row = $('<tr>')
          .append($('<td>', { text: op.entity_id }))
          .append($('<td>', { text: op.display_name || '' }))
          .append(OidcFederation.statusCell(op))
          .append($('<td>', { text: op.last_resolved || '-' }));
      const actions = $('<td>');
      if (op.configured) {
        actions.append($('<button>', {
          type: 'button',
          class: 'btn btn-sm btn-outline-primary',
          text: 'Metadata'
        }).on('click', () => OidcFederation.showOpMetadata(op.entity_id)));
      }
      tbody.append(row.append(actions));
    }
  }

  /**
   * The status of a provider - whether it was resolved during the latest check, and if not, what happened. A
   * provider that could not be resolved is kept with the configuration from the last successful resolution, which
   * is what the badge says.
   */
  static statusCell(op) {
    const cell = $('<td>');
    if (op.status === 'ok') {
      return cell.append($('<span>', {
        class: 'badge bg-success',
        text: 'Configured',
        title: 'Resolved during the latest check'
      }));
    }
    const text = op.status === 'not_listed' ? 'Not listed' : 'Resolve failed';
    const suffix = op.configured
        ? ' The previously resolved configuration is still used.'
        : ' The provider has never been successfully resolved and cannot be used.';
    cell.append($('<span>', {
      class: 'badge ' + (op.configured ? 'bg-warning text-dark' : 'bg-danger'),
      text: text,
      title: (op.error || 'The federation no longer lists the provider') + suffix
    }));
    if (op.error) {
      cell.append($('<div>', { class: 'small text-muted', text: op.error }));
    }
    return cell;
  }

  /**
   * Renders a number of seconds as minutes/hours where that is more readable.
   */
  static duration(seconds) {
    if (seconds % 3600 === 0) {
      return (seconds / 3600) + (seconds === 3600 ? ' hour' : ' hours');
    }
    if (seconds % 60 === 0) {
      return (seconds / 60) + (seconds === 60 ? ' minute' : ' minutes');
    }
    return seconds + ' seconds';
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
