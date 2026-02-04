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

class TestClient {

  constructor() {
    this.samlAuthentication = null;
    this.oidcAuthentication = null;
    this.oidcRelyingParties = null;

    $('.noscripthide').show();
    $('[data-bs-toggle="tooltip"]').tooltip();

    $('#menu-home').click((event) => {
      appState.setSelectedFeature('home');
      this.onNavbarClicked(event, 'home');
    });

    $('#menu-saml').click((event) => {
      if (TestClient.isSamlEnabled()) {
        let scrollCb = null;
        if (this.samlAuthentication === null) {
          this.samlAuthentication = new SamlAuthentication();
        }
        else {
          scrollCb = () => this.samlAuthentication.scrollToActiveView();
        }
        appState.setSelectedFeature('saml');
        this.onNavbarClicked(event, 'saml', scrollCb);
      }
    });

    $('#menu-saml-clients').click((event) => {
      appState.setSelectedFeature('saml-clients');
      this.onNavbarClicked(event, 'saml-clients');
      displaySamlSps();
    });

    $('#menu-saml-metadata').click((event) => {
      appState.setSelectedFeature('saml-metadata');
      this.onNavbarClicked(event, 'saml-metadata');
      displayFederationInfo();
    });

    $('#menu-oidc').click((event) => {
      if(TestClient.isOidcEnabled()) {
        let scrollCb = null;
        if (this.oidcAuthentication === null) {
          this.oidcAuthentication = new OIDCAuthentication();
        }
        else {
          scrollCb = () => this.oidcAuthentication.scrollToActiveView();
        }
        appState.setSelectedFeature('oidc');
        this.onNavbarClicked(event, 'oidc', scrollCb);
      }
    });

    $('#menu-oidc-clients').click((event) => {
      if (TestClient.isOidcEnabled()) {
        if (!this.oidcRelyingParties) {
          this.oidcRelyingParties = new OidcRelyingParties();
        }
        this.oidcRelyingParties.display();
        appState.setSelectedFeature('oidc-clients');
        this.onNavbarClicked(event, 'oidc-clients');
      }
    });

  }

  static init() {
    const testClient = new TestClient();

    if (!TestClient.isSamlEnabled()) {
      $('#menu-saml').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
      $('#menu-saml-clients').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
      $('#menu-saml-metadata').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
      $('#main-description-saml-fed-info').hide();
    }
    if (!TestClient.isOidcEnabled()) {
      $('#menu-oidc').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
      $('#menu-oidc-clients').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
      $('#menu-oidc-ops').addClass("disabled")
          .attr("aria-disabled", "true")
          .attr("tabindex", "-1");
    }

    $('#main-description-saml-fed-info-name').text(TestClient.getFederationName());

    let feature = appState.getSelectedFeature();
    if (feature) {
      $("#menu-" + feature).trigger('click');
    }
    else {
      testClient.onNavbarClicked(null, 'home');
    }

    const copyButton = $('#copy-to-clipboard-button');
    copyButton
        .off('click')
        .on('click', function () {
          let json = $('#json-content').prop('json')
          navigator.clipboard.writeText(json);
          const toast = document.getElementById('copy-toast');
          toast.classList.add('show');

          setTimeout(() => {
            toast.classList.remove('show');
          }, 1500);
        });
  }

  static isSamlEnabled() {
    return window.app_info && window.app_info.saml_enabled;
  }

  static isOidcEnabled() {
    return window.app_info && window.app_info.oidc_enabled;
  }

  static getFederationName() {
    if (window.app_info) {
      return window.app_info.federation_name;
    }
    else {
      return "???";
    }
  }

  onNavbarClicked(event, name, fn = null) {
    if (event != null) {
      event.preventDefault();
    }
    $('.main-div').hide();
    $("#main-" + name).show();
    if (fn) {
      fn();
    }
  }

}

function generateRandomId(prefix = 'id') {
  return prefix + '_' + Math.random().toString(36).slice(2, 11);
}

$(document).ready(function() {
  TestClient.init();
});

class CodeViewer {

  constructor() {
    this.formatterPars = {
      indentation: '  ',
      collapseContent: true,
      throwOnFailure: false
    };

    this.jsonFormat = {
      indent: 2,
      trailingCommas: true
    };

    hljs.configure({
      ignoreUnescapedHTML: true,
      throwUnescapedHTML: false,
      languages: [ 'xml', 'json' ]
    });
  }

  displayXml(title, xml) {
    const formattedXml = xmlFormatter(xml, this.formatterPars);

    const xmlElement = $('#xml-content');

    xmlElement.text(formattedXml);
    xmlElement.removeAttr('data-highlighted');
    hljs.highlightElement(xmlElement.get(0));

    const xmlViewer = $('#xml-viewer');
    xmlViewer.find('.modal-title').text(title);
    xmlViewer.find('.modal').modal('show');
  }

  displayJson(title, json) {
    const formatted = prettyPrintJson.toHtml(json, this.jsonFormat);
    const content = $('#json-content');
    content.html(formatted);
    content.prop('json', json);

    const jsonViewer = $('#json-viewer');
    jsonViewer.find('.modal-title').text(title);
    jsonViewer.find('.modal').modal('show');
  }

  displayURL(title, text) {
    $('#json-content').html(text.replace(/.*\?/g, '$&\n\t').replace(/&/g, '$&\n\t'));

    const jsonViewer = $('#json-viewer');
    jsonViewer.find('.modal-title').text(title);
    jsonViewer.find('.modal').modal('show');
  }
}

const codeViewer = new CodeViewer();

function redirectBrowser(url) {
  window.location.href = url;
}

function buildUrl(path) {
  var base = $("#base-href-id").prop('href');
  if (base.endsWith('/')) {
    base = base.slice(0, -1);
  }
  return base + path;
}

function postBrowser(url, pars) {
  let form = $('<form>', {
    action: url,
    method: 'POST'
  });

  $.each(pars, function(key, value) {
    form.append($('<input>', {
      type: 'hidden',
      name: key,
      value: value
    }));
  });

  $('body').append(form);
  form.submit();
}
