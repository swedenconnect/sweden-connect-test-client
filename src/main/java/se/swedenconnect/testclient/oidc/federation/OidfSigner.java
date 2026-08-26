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
package se.swedenconnect.testclient.oidc.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;
import se.swedenconnect.testclient.utils.JoseUtils;
import se.swedenconnect.testclient.utils.JwkUtils;


/**
 * Signs OpenID Federation statements (entity configurations and subordinate statements) using a
 * {@link PkiCredential}.
 *
 * @author Felix Hellman
 */
public class OidfSigner {

  /** The credential used for signing. */
  private final PkiCredential credential;

  /** The public JWK (including its key ID) of the signing credential. */
  @Getter
  private final JWK publicJwk;

  /** The JWS algorithm to use. */
  @Getter
  private final JWSAlgorithm algorithm;

  /**
   * Constructor.
   *
   * @param credential the credential to sign federation statements with
   */
  public OidfSigner(@Nonnull final PkiCredential credential) {
    this.credential = credential;
    final JWK jwk = new JwkTransformerFunction().serializable().apply(credential).toPublicJWK();
    this.algorithm = JoseUtils.signingAlgorithm(jwk);
    this.publicJwk = JwkUtils.declareUse(jwk, KeyUse.SIGNATURE, this.algorithm);
  }

  /**
   * Gets the JWK set to publish as the entity's federation keys.
   *
   * @return a {@link JWKSet} holding the public federation key
   */
  @Nonnull
  public JWKSet getJwkSet() {
    return new JWKSet(this.publicJwk);
  }

  /**
   * Signs the supplied claims set.
   *
   * @param claims the claims to sign
   * @param type the JOSE {@code typ} header value
   * @return a signed JWT
   * @throws JOSEException for signature errors
   */
  @Nonnull
  public SignedJWT sign(@Nonnull final JWTClaimsSet claims, @Nonnull final JOSEObjectType type) throws JOSEException {
    final JWSHeader header = new JWSHeader.Builder(this.algorithm)
        .type(type)
        .keyID(this.publicJwk.getKeyID())
        .build();
    final SignedJWT jwt = new SignedJWT(header, claims);
    jwt.sign(this.createSigner());
    return jwt;
  }

  @Nonnull
  private JWSSigner createSigner() throws JOSEException {
    return JoseUtils.signer(this.credential);
  }

}
