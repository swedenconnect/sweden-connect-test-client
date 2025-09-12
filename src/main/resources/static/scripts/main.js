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

    $('.noscripthide').show();
    $('[data-bs-toggle="tooltip"]').tooltip();

    $('#menu-home').click((event) => {
      appState.setSelectedFeature('home');
      this.onNavbarClicked(event, 'home');
    });

    $('#menu-saml').click((event) => {
      let scrollCb = null;
      if (this.samlAuthentication === null) {
        this.samlAuthentication = new SamlAuthentication();
      }
      else {
        scrollCb = () => this.samlAuthentication.scrollToActiveView();
      }
      appState.setSelectedFeature('saml');
      this.onNavbarClicked(event, 'saml', scrollCb);
    });

    $('#menu-oidc').click((event) => {
      appState.setSelectedFeature('oidc');
      this.onNavbarClicked(event, 'oidc');
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
  }

  static init() {
    const testClient = new TestClient();

    let feature = appState.getSelectedFeature();
    if (feature) {
      $("#menu-" + feature).trigger('click');
    }
    else {
      testClient.onNavbarClicked(null, 'home');
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

    hljs.configure({
      ignoreUnescapedHTML: true,
      throwUnescapedHTML: false,
      languages: [ 'xml', 'json' ]
    });
  }

  displayXml(title, xml) {
    let formattedXml = xmlFormatter(xml, this.formatterPars);

    let xmlElement = $('#xml-content');

    xmlElement.text(formattedXml);
    xmlElement.removeAttr('data-highlighted');
    hljs.highlightElement(xmlElement.get(0));

    let xmlViewer = $('#xml-viewer');
    xmlViewer.find('.modal-title').text(title);
    xmlViewer.find('.modal').modal('show');
  }

}

const codeViewer = new CodeViewer();

function redirectBrowser(url) {
  window.location.href = url;
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
