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


/**
 * Implements state and storage.
 */
class State {

  /**
   * Constructor.
   *
   * @param localStorageKey the name for the key used for local storage
   * @param sessionStorageKey the name for the key used for session storage
   */
  constructor(localStorageKey, sessionStorageKey) {
    this.local_storage_key = localStorageKey;
    this.session_storage_key = sessionStorageKey;

    this.storage = JSON.parse(localStorage.getItem(this.local_storage_key) || '{}');
    this.session = JSON.parse(sessionStorage.getItem(this.session_storage_key) || '{}');

    State._merge(this.storage, this.session);

    $(window).on("pagehide beforeunload", () => {
      localStorage.setItem(this.local_storage_key, JSON.stringify(this.storage));
      sessionStorage.setItem(this.session_storage_key, JSON.stringify(this.session));
    });
  }

  /**
   * Gets the object found at the given keyPath (i.e., "foo" or "foo.bar").
   * @param keyPath the key or key path (dot-separated)
   * @param clone whether the returned object should be cloned
   * @returns the object, or null/undefined
   */
  get(keyPath, clone = false) {
    const val = keyPath.split('.').reduce((obj, key) => {
      return obj && obj[key] !== undefined ? obj[key] : undefined;
    }, this.session);
    return clone ? State._clone(val) : val;
  }

  /**
   * Assigns the given value to the given key (key path)
   * @param keyPath the key or key path (dot-separated)
   * @param value the value
   * @param persist whether the setting should be persisted (in local storage)
   * @param writeCache whether we should update storage in browser directly
   */
  set(keyPath, value, persist = false, writeCache = false) {
    this._set(keyPath, value, this.session);
    if (writeCache) {
      sessionStorage.setItem(this.session_storage_key, JSON.stringify(this.session));
    }
    if (persist) {
      this._set(keyPath, value, this.storage);
      if (writeCache) {
        localStorage.setItem(this.local_storage_key, JSON.stringify(this.storage));
      }
    }
  }

  _set(path, value, target) {
    const keys = path.split('.');
    let obj = target;

    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i];
      if (!obj[key] || typeof obj[key] !== "object") {
        obj[key] = {}; // create intermediate object if missing
      }
      obj = obj[key];
    }
    obj[keys[keys.length - 1]] = value;
  }

  static _merge(source, target) {
    for (const key of Object.keys(source)) {
      if (
          source[key] &&
          typeof source[key] === "object" &&
          !Array.isArray(source[key])
      ) {
        // ensure target[key] is an object
        if (!target[key] || typeof target[key] !== "object") {
          target[key] = {};
        }
        State._merge(source[key], target[key]); // recurse
      }
      else {
        // primitives and arrays just overwrite
        target[key] = source[key];
      }
    }
    return target;
  }

  static _clone(obj) {
    if (obj === null || obj === undefined) {
      return null;
    }

    const type = typeof obj;
    if (type === 'object') {

      // Prefer structuredClone if available (modern browsers / Node 17+)
      if (typeof structuredClone === "function") {
        return structuredClone(obj);
      }

      // Fallback to JSON round-trip (works for JSON-safe data only)
      return JSON.parse(JSON.stringify(obj));
    }
    else {
      return obj;
    }
  }
}
class AppState {

  constructor() {

    this._app_state = JSON.parse(localStorage.getItem('sctc.app') || '{}');

    $(window).on("pagehide beforeunload", () => {
      localStorage.setItem('sctc.app', JSON.stringify(this._app_state));
    });
  }

  getSelectedFeature() {
    return this._app_state.selected_feature;
  }

  setSelectedFeature(feature) {
    this._app_state.selected_feature = feature;
  }

}

//
// The app state object
//
let appState = new AppState();


$(document).ready(function() {
})
