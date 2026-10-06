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
package se.swedenconnect.testclient.oidc;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import jakarta.annotation.Nonnull;
import lombok.Getter;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.controllers.OidcRpLogoController;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.utils.JwkUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Representation of an OIDC RP.
 *
 * @author Martin Lindström
 */
public class OidcRp {

  private static final JSONParser jsonParser = new JSONParser(JSONParser.MODE_PERMISSIVE);

  /** Suffix added to the key ID of the encryption JWK when the encryption key is also a signing key. */
  public static final String ENCRYPTION_KID_SUFFIX = "-enc";

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

  /** Whether the RP's keys are published via {@code jwks_uri} rather than embedded in the metadata. */
  @Getter
  private final boolean useJwksUrl;

  /** The URL where this RP:s JWKS is published. Only meaningful when {@link #useJwksUrl} is {@code true}. */
  @Getter
  private final String jwksUri;

  /** Whether an OpenID Federation entity configuration is set up (and published) for the RP. */
  private final boolean entityConfiguration;

  /** The RP:s public key set. */
  @Getter
  private final JWKSet jwkSet;

  private final OIDCClientMetadata metadata;

  public OidcRp(@Nonnull final String entityId, @Nonnull final String description,
      @Nonnull final String pathSuffix, @Nonnull final ClientCredentials clientCredentials,
      @Nonnull final String metadataJson, @Nonnull final String redirectUri,
      final boolean useJwksUrl, @Nonnull final String jwksUri, final boolean entityConfiguration)
      throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
    this.entityId = entityId;
    this.description = description;
    this.pathSuffix = pathSuffix;
    this.credentials = clientCredentials;
    this.useJwksUrl = useJwksUrl;
    this.jwksUri = jwksUri;
    this.entityConfiguration = entityConfiguration;

    final String resolvedMetadataJson =
        metadataJson.replace(OidcRpLogoController.LOGO_PLACEHOLDER, entityId + "/logo.svg");
    final JSONObject json = (JSONObject) jsonParser.parse(resolvedMetadataJson);
    this.metadata = OIDCClientMetadata.parse(json);
    this.metadata.setRedirectionURI(URI.create(redirectUri));

    this.jwkSet = createJwkSet(this.credentials);

    if (this.useJwksUrl) {
      this.metadata.setJWKSetURI(URI.create(this.jwksUri));
    }
    else {
      this.metadata.setJWKSet(this.jwkSet);
    }

    // this.metadata.toJSONObject(true).toJSONString();

    // this.metadata.setRedirectionURI();
    // this.metadata.setJWKSet();

    // OIDCProviderMetadata
    // OIDCProviderConfigurationRequest

  }

  /**
   * Creates the public key set of the RP. All active signing credentials are published with {@code use: sig}, and the
   * current encryption credential with {@code use: enc}. The previous encryption credential is not published, it is
   * only used for decryption after a key rollover.
   * <p>
   * If the encryption key is also a signing key, it is published once per use. The OP selects keys by {@code kid} and
   * {@code use}, so the encryption JWK then gets the key ID suffixed with {@value #ENCRYPTION_KID_SUFFIX}.
   * </p>
   *
   * @param credentials the RP credentials
   * @return the public key set
   */
  @Nonnull
  private static JWKSet createJwkSet(@Nonnull final ClientCredentials credentials) {
    final JwkTransformerFunction jwkTransformer = new JwkTransformerFunction();
    final List<PkiCredential> signingCredentials = credentials.getCredentialsForSigning();
    final List<JWK> keys = new ArrayList<>(signingCredentials.stream()
        .map(credential -> JwkUtils.declareUse(jwkTransformer.apply(credential), KeyUse.SIGNATURE, null))
        .toList());

    final PkiCredential encryptionCredential = credentials.getCredentialsForEncryption().getFirst();
    JWK encryptionKey = JwkUtils.declareUse(jwkTransformer.apply(encryptionCredential), KeyUse.ENCRYPTION, null);
    final boolean sharedKey = signingCredentials.stream()
        .anyMatch(c -> c.getPublicKey().equals(encryptionCredential.getPublicKey()));
    if (sharedKey) {
      encryptionKey = withKeyId(encryptionKey, encryptionKey.getKeyID() + ENCRYPTION_KID_SUFFIX);
    }
    keys.add(encryptionKey);

    return new JWKSet(keys).toPublicJWKSet();
  }

  /**
   * Gives a copy of a JWK with another key ID.
   *
   * @param jwk the JWK
   * @param keyId the key ID
   * @return a JWK with the given key ID
   */
  @Nonnull
  private static JWK withKeyId(@Nonnull final JWK jwk, @Nonnull final String keyId) {
    final Map<String, Object> json = new LinkedHashMap<>(jwk.toJSONObject());
    json.put("kid", keyId);
    try {
      return JWK.parse(json);
    }
    catch (final java.text.ParseException e) {
      throw new IllegalArgumentException("Failed to assign key ID %s".formatted(keyId), e);
    }
  }

  /**
   * Gets the RP metadata.
   *
   * @return the RP metadata
   */
  @Nonnull
  public OIDCClientMetadata getMetadata() {
    return this.metadata;
  }

  /**
   * Tells whether an OpenID Federation entity configuration is set up for the RP. This is never the case when OpenID
   * Federation support is disabled.
   *
   * @return {@code true} if the RP has an entity configuration, and {@code false} otherwise
   */
  public boolean hasEntityConfiguration() {
    return this.entityConfiguration;
  }
}
