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
package se.swedenconnect.testclient.controllers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * Applies the Sweden Connect specific extensions - the user message and the sign message - to the authentication
 * request that is being built.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
public class AuthorizationRequestCustomizer {

  /**
   * Applies the parameters of the request URL, and the request object, to the request builder.
   * <p>
   * The user message is sent as a JSON object serialized into the parameter, and the sign request as a JWT whose claims
   * set is the sign request object.
   * </p>
   *
   * @param builder the request builder
   * @param jwkFunction function giving the key for a key ID
   * @param resolver the resolver for the request URL
   * @return the builder
   * @throws JOSEException for signing or encryption errors
   * @throws ParseException for invalid parameter values
   */
  public static AuthenticationRequest.Builder customize(
      final AuthenticationRequest.Builder builder,
      final Function<String, JWK> jwkFunction,
      final AuthorizationParameterResolver resolver
  ) throws JOSEException, ParseException {

    resolver.getUserMessage().ifPresent(um -> builder.customParameter(OidcMessageSerializer.USER_MESSAGE,
        JSONObjectUtils.toJSONString(OidcMessageSerializer.toUserMessage(um))));
    resolver.getSignRequestJWT(jwkFunction).ifPresent(jwt ->
        builder.customParameter(OidcMessageSerializer.SIGN_REQUEST, jwt.serialize()));

    resolver.getNonce().ifPresent(builder::nonce);
    resolver.getState().ifPresent(builder::state);
    resolver.getRedirectionURI().ifPresent(builder::redirectionURI);
    resolver.requestBody(jwkFunction).ifPresent(builder::requestObject);
    resolver.getAcrValues().ifPresent(builder::acrValues);
    resolver.getPrompt().ifPresent(builder::prompt);
    // The request library requires openid in the scope. What the URL actually carries is decided by toURI.
    resolver.getScope().map(AuthorizationRequestCustomizer::withOpenid).ifPresent(builder::scope);
    resolver.getResponseType().ifPresent(builder::responseType);
    resolver.getLoginHint().ifPresent(builder::loginHint);
    resolver.getCodeChallenge().ifPresent(cc -> {
      builder.codeChallenge(cc.getRight(), cc.getLeft());
    });
    resolver.getClaimRequest().ifPresent(builder::claims);
    return builder;
  }

  /**
   * Gets the parameters that are sent for an authentication request - in the query string for GET and as a form body
   * for POST.
   * <p>
   * The request library insists on {@code client_id}, {@code response_type}, a {@code scope} containing
   * {@code openid} and (without a request object) {@code redirect_uri}. The parameters are therefore the request's
   * parameters with these four set exactly as the resolver places them, so that each is present only when selected
   * for the URL.
   * </p>
   *
   * @param request the authentication request built by {@link #customize}
   * @param resolver the resolver for the request URL
   * @return the parameters to send
   */
  public static Map<String, List<String>> toParameters(
      final AuthenticationRequest request, final AuthorizationParameterResolver resolver) {
    final Map<String, List<String>> parameters = new LinkedHashMap<>(request.toParameters());
    setOrRemove(parameters, "client_id", resolver.getClientId().map(ClientID::getValue));
    setOrRemove(parameters, "response_type", resolver.getResponseType().map(ResponseType::toString));
    setOrRemove(parameters, "redirect_uri", resolver.getRedirectionURI().map(URI::toString));
    setOrRemove(parameters, "scope", resolver.getScope().map(Scope::toString));
    return parameters;
  }

  /**
   * Gets the URI that is sent for an authentication request with GET, i.e., the authorization endpoint with the
   * parameters from {@link #toParameters} added to its query string.
   *
   * @param request the authentication request built by {@link #customize}
   * @param resolver the resolver for the request URL
   * @return the URI to send
   */
  public static URI toURI(final AuthenticationRequest request, final AuthorizationParameterResolver resolver) {
    final String endpoint = request.getEndpointURI().toString();
    final String query = URLUtils.serializeParameters(toParameters(request, resolver));
    if (query.isEmpty()) {
      return URI.create(endpoint);
    }
    return URI.create(endpoint + (request.getEndpointURI().getRawQuery() != null ? "&" : "?") + query);
  }

  /**
   * Gets the authentication request as it is sent with a given method. For GET it is the URI from {@link #toURI}, for
   * POST the authorization endpoint as configured, including any query string of its own, along with the parameters
   * from {@link #toParameters} as form parameters.
   *
   * @param request the authentication request built by {@link #customize}
   * @param resolver the resolver for the request URL
   * @param method the HTTP method
   * @return the request to send
   */
  public static SentAuthorizationRequest toSentRequest(final AuthenticationRequest request,
      final AuthorizationParameterResolver resolver, final SentAuthorizationRequest.Method method) {
    return switch (method) {
      case GET -> new SentAuthorizationRequest(method, toURI(request, resolver).toASCIIString(), null);
      case POST -> new SentAuthorizationRequest(
          method, request.getEndpointURI().toASCIIString(), toParameters(request, resolver));
    };
  }

  private static void setOrRemove(
      final Map<String, List<String>> parameters, final String name, final Optional<String> value) {
    value.ifPresentOrElse(v -> parameters.put(name, List.of(v)), () -> parameters.remove(name));
  }

  private static Scope withOpenid(final Scope scope) {
    if (scope.contains(OIDCScopeValue.OPENID)) {
      return scope;
    }
    final Scope scopeWithOpenid = new Scope(OIDCScopeValue.OPENID);
    scopeWithOpenid.addAll(scope);
    return scopeWithOpenid;
  }
}
