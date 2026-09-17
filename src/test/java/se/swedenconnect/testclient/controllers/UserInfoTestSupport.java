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

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.springframework.mock.web.MockHttpSession;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

/**
 * An RP, an OP, and an authentication in the session - for the tests of the UserInfo call.
 *
 * @author Martin Lindström
 */
final class UserInfoTestSupport {

  static final String RP = "https://rp.example.com/rp";
  static final String OP = "https://op.example.com";
  static final String TOKEN_ENDPOINT = OP + "/token";
  static final String USERINFO_ENDPOINT = OP + "/userinfo";
  static final String ACCESS_TOKEN = "the-access-token";

  static final String NATURAL_PERSON_INFO = "https://id.oidc.se/scope/naturalPersonInfo";
  static final String NATURAL_PERSON_NUMBER = "https://id.oidc.se/scope/naturalPersonNumber";
  static final String PERSONAL_IDENTITY_NUMBER = "https://id.oidc.se/claim/personalIdentityNumber";

  private UserInfoTestSupport() {
  }

  static OidcRp rp() {
    try {
      final RSAKey key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
      final PkiCredential credential = new BasicCredential(key.toPublicKey(), key.toPrivateKey());
      final ClientCredentials credentials =
          new ClientCredentials(credential, null, credential, null, credential, credential, credential);
      return new OidcRp(RP, "Test RP", "rp", credentials, """
          {
            "response_types" : [ "code" ],
            "grant_types" : [ "authorization_code" ],
            "client_name" : "Test RP",
            "token_endpoint_auth_method" : "private_key_jwt"
          }
          """, RP + "/redirect", false, RP + "/jwks", false);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to create test RP", e);
    }
  }

  static OidcOp op() {
    return OidcOp.builder()
        .entityId(OP)
        .authorizationEndpoint(OP + "/authorize")
        .tokenEndpoint(TOKEN_ENDPOINT)
        .userInfoEndpoint(USERINFO_ENDPOINT)
        .build();
  }

  /**
   * An authentication request for the naturalPersonInfo and naturalPersonNumber scopes that also requests the
   * {@code birthdate} claim from UserInfo.
   */
  static AuthenticationRequest authRequest() {
    final OIDCClaimsRequest claims = new OIDCClaimsRequest()
        .withUserInfoClaimsRequest(new ClaimsSetRequest().add("birthdate"));
    return new AuthenticationRequest.Builder(new ResponseType("code"),
        new Scope("openid", NATURAL_PERSON_INFO, NATURAL_PERSON_NUMBER), new ClientID(RP), URI.create(RP + "/redirect"))
        .endpointURI(URI.create(OP + "/authorize"))
        .state(new State())
        .nonce(new Nonce())
        .claims(claims)
        .build();
  }

  /**
   * Puts an authentication - request, OP and RP - in the session, as {@link OidcRestController} does when the
   * authentication request is generated.
   */
  static void authenticationInSession(final MockHttpSession session, final OidcRp rp) {
    session.setAttribute("auth_request", authRequest());
    session.setAttribute("selected_op", op());
    session.setAttribute("selected_rp", rp);
  }

  /** A token response with an access token and an unsigned ID token holding a personal identity number. */
  static String tokenResponse() {
    final String idToken = new PlainJWT(new JWTClaimsSet.Builder()
        .issuer(OP)
        .subject("user")
        .audience(RP)
        .claim(PERSONAL_IDENTITY_NUMBER, "196911292032")
        .build()).serialize();
    return """
        { "access_token": "%s", "token_type": "Bearer", "id_token": "%s" }""".formatted(ACCESS_TOKEN, idToken);
  }

  static Map<String, Object> idTokenClaims() {
    return Map.of("sub", "user", PERSONAL_IDENTITY_NUMBER, "196911292032");
  }
}
