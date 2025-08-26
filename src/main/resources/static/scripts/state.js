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

//
// The app state object
//
let appState = {
  _app_state: null,

  // getSelectedFeature
  //
  getSelectedFeature: function() {
    return this._get_app_state().selected_feature;
  },

  // setSelectedFeature
  //
  setSelectedFeature: function(feature) {
    this._get_app_state().selected_feature = feature;
    localStorage.setItem('sctc.app', JSON.stringify(this._app_state));
  },

  _get_app_state: function() {
    if (this._app_state == null) {
      this._app_state = JSON.parse(localStorage.getItem('sctc.app') || "{}");
    }
    return this._app_state;
  }

};

//
// The SAML state object
//
let samlState = {
  // The storage object (will be written to local storage)
  storage: {},

  // Cached SP info
  spInfoCache: null,

  // Cached IdP info
  idpInfoCache: null,

  // Whether we are in build authn state
  buildAuthnState: false,

  // The authnRequest pars
  authnRequest: null,

  // init
  //  initializes the state
  //
  init: function() {
    this.storage = JSON.parse(localStorage.getItem('sctc.saml') || "{}");
  },

  // getSelectedSp
  //  returns the currently selected SP (may be null)
  //
  getSelectedSp: function() {
    return this.storage.selectedSp;
  },

  // setSelectedSp
  //  assigns the selected SP (and updates the local storage state)
  //
  setSelectedSp: function(sp) {
    this.storage.selectedSp = sp;
    localStorage.setItem('sctc.saml', JSON.stringify(this.storage));
  },

  // getSelectedIdp
  //  returns the currently selected IdP (may be null)
  //
  getSelectedIdp: function() {
    return this.storage.selectedIdp;
  },

  // setSelectedIdp
  //  assigns the selected IdP (and updates the local storage state)
  //
  setSelectedIdp: function(idp) {
    this.storage.selectedIdp = idp;
    localStorage.setItem('sctc.saml', JSON.stringify(this.storage));
  }

};

$(document).ready(function() {

  samlState.init();

})
