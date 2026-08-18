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
package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import jakarta.annotation.Nonnull;
import lombok.Getter;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.utils.JwkUtils;

import java.net.URI;

/**
 * Representation of an OIDC RP.
 *
 * @author Martin Lindström
 */
public class OidcRp {

  private static final JSONParser jsonParser = new JSONParser(JSONParser.MODE_PERMISSIVE);

  /** The Entity Identifier of the client. */
  @Getter
  private final String entityId;

  /** RP description. */
  @Getter
  private final String description;

  /** Suffix for OIDC paths. */
  @Getter
  private final String pathSuffix;

  /** The RP client credentials. */
  @Getter
  private final ClientCredentials credentials;

  private final OIDCClientMetadata metadata;

  public OidcRp(@Nonnull final String entityId, @Nonnull final String description,
      @Nonnull final String pathSuffix, @Nonnull final ClientCredentials clientCredentials,
      @Nonnull final String metadataJson, @Nonnull final String redirectUri)
      throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
    this.entityId = entityId;
    this.description = description;
    this.pathSuffix = pathSuffix;
    this.credentials = clientCredentials;

    final JSONObject json = (JSONObject) jsonParser.parse(metadataJson);
    this.metadata = OIDCClientMetadata.parse(json);
    this.metadata.setRedirectionURI(URI.create(redirectUri));

    final JwkTransformerFunction jwkTransformer = new JwkTransformerFunction();
    // TODO: other metadata
    final JWKSet jwkSet = new JWKSet(JwkUtils.declareUse(
        jwkTransformer.apply(this.credentials.getCredentialForSigning()), KeyUse.SIGNATURE, null));

    this.metadata.setJWKSet(jwkSet.toPublicJWKSet());

    // this.metadata.toJSONObject(true).toJSONString();

    // this.metadata.setRedirectionURI();
    // this.metadata.setJWKSet();

    // OIDCProviderMetadata
    // OIDCProviderConfigurationRequest

  }

  @Nonnull
  public OIDCClientMetadata getMetadata() {
    return this.metadata;
  }
}
