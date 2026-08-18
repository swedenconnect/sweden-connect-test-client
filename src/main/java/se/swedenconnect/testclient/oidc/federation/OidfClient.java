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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.trust.EntityStatementRetriever;
import com.nimbusds.openid.connect.sdk.federation.trust.ResolveException;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * An OpenID Federation client. Implements {@link EntityStatementRetriever} so that it may be plugged into the Nimbus
 * trust chain resolver, and adds support for subordinate listings and (signed) JWK set downloads.
 * <p>
 * All HTTP calls are made using the application's {@link RestClient}, meaning that the configured TLS settings apply.
 * </p>
 *
 * @author Felix Hellman
 */
@Slf4j
public class OidfClient implements EntityStatementRetriever {

  /** The well-known path where entity configurations are published. */
  public static final String ENTITY_CONFIGURATION_PATH = "/.well-known/openid-federation";

  /** The HTTP client. */
  private final RestClient client;

  /**
   * Constructor.
   *
   * @param client the REST client to use
   */
  public OidfClient(@Nonnull final RestClient client) {
    this.client = client;
  }

  /**
   * Calculates the URL where the entity configuration for the given entity is published.
   *
   * @param entityId the entity identifier
   * @return the entity configuration URL
   */
  @Nonnull
  public static String entityConfigurationUrl(@Nonnull final String entityId) {
    final String base = entityId.endsWith("/")
        ? entityId.substring(0, entityId.length() - 1)
        : entityId;
    return base + ENTITY_CONFIGURATION_PATH;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public EntityStatement fetchEntityConfiguration(@Nonnull final EntityID entityID) throws ResolveException {
    final URI url = URI.create(entityConfigurationUrl(entityID.getValue()));
    log.debug("Fetching entity configuration from {}", url);
    try {
      return EntityStatement.parse(this.getString(url));
    }
    catch (final Exception e) {
      throw new ResolveException("Failed to fetch entity configuration for " + entityID + " (" + url + ")", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public EntityStatement fetchEntityStatement(@Nonnull final URI federationAPIEndpoint,
      @Nonnull final EntityID issuer, @Nonnull final EntityID subject) throws ResolveException {

    final URI url = UriComponentsBuilder.fromUri(federationAPIEndpoint)
        .queryParam("sub", subject.getValue())
        .build()
        .encode()
        .toUri();
    log.debug("Fetching subordinate statement for {} from {}", subject, url);
    try {
      return EntityStatement.parse(this.getString(url));
    }
    catch (final Exception e) {
      throw new ResolveException(
          "Failed to fetch subordinate statement for " + subject + " from " + issuer, e);
    }
  }

  /**
   * Invokes the resolve endpoint of a trust anchor. The returned JWT is not verified - it is up to the caller to
   * validate its signature against the trust anchor keys.
   *
   * @param resolveEndpoint the resolve endpoint of the trust anchor
   * @param subject the entity to resolve
   * @param trustAnchor the trust anchor to resolve under
   * @param entityType optional entity type to limit the resolved metadata to
   * @return the resolve response (a signed JWT of type {@code resolve-response+jwt})
   */
  @Nonnull
  public SignedJWT resolve(@Nonnull final URI resolveEndpoint, @Nonnull final EntityID subject,
      @Nonnull final EntityID trustAnchor, @Nullable final EntityType entityType) {

    final UriComponentsBuilder builder = UriComponentsBuilder.fromUri(resolveEndpoint)
        .queryParam("sub", subject.getValue())
        .queryParam("trust_anchor", trustAnchor.getValue());
    if (entityType != null) {
      builder.queryParam("entity_type", entityType.getValue());
    }
    final URI url = builder.build().encode().toUri();
    log.debug("Resolving {} under {} using {}", subject, trustAnchor, url);

    final String response;
    try {
      response = this.getString(url);
    }
    catch (final RestClientResponseException e) {
      // The federation API reports errors as a JSON object holding error and error_description - include it.
      throw new IllegalArgumentException("The resolve endpoint %s responded with %s: %s"
          .formatted(url, e.getStatusCode(), e.getResponseBodyAsString()), e);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to invoke the resolve endpoint " + url, e);
    }
    try {
      return SignedJWT.parse(response);
    }
    catch (final java.text.ParseException e) {
      throw new IllegalArgumentException("The resolve endpoint " + url + " did not return a signed JWT", e);
    }
  }

  /**
   * Invokes the subordinate listing endpoint of an authority.
   *
   * @param federationListEndpoint the federation list endpoint
   * @param entityType optional entity type to filter the listing on
   * @return a list of entity identifiers
   */
  @Nonnull
  public List<EntityID> listSubordinates(@Nonnull final URI federationListEndpoint,
      @Nullable final EntityType entityType) {

    final UriComponentsBuilder builder = UriComponentsBuilder.fromUri(federationListEndpoint);
    if (entityType != null) {
      builder.queryParam("entity_type", entityType.getValue());
    }
    final URI url = builder.build().encode().toUri();
    log.debug("Listing subordinates from {}", url);

    final List<String> entities = this.client.get()
        .uri(url)
        .retrieve()
        .body(new ParameterizedTypeReference<List<String>>() {
        });

    if (entities == null) {
      return List.of();
    }
    return entities.stream()
        .filter(Objects::nonNull)
        .map(EntityID::new)
        .toList();
  }

  /**
   * Fetches the entity configuration of the given entity, as it was published - i.e., without interpreting it as a
   * Nimbus {@link EntityStatement}.
   *
   * @param entityId the entity identifier
   * @return the entity configuration (a signed JWT of type {@code entity-statement+jwt})
   */
  @Nonnull
  public SignedJWT fetchSignedEntityConfiguration(@Nonnull final String entityId) {
    final URI url = URI.create(entityConfigurationUrl(entityId));
    log.debug("Fetching entity configuration from {}", url);
    final String response;
    try {
      response = this.getString(url);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException(
          "Failed to fetch the entity configuration for %s (%s): %s".formatted(entityId, url, message(e)), e);
    }
    try {
      return SignedJWT.parse(response);
    }
    catch (final java.text.ParseException e) {
      throw new IllegalArgumentException(url + " did not return a signed entity statement", e);
    }
  }

  /**
   * Invokes the trust mark endpoint of a trust mark issuer. The returned JWT is not verified - it is up to the
   * caller to validate it against the issuer's keys.
   *
   * @param trustMarkEndpoint the trust mark endpoint of the issuer
   * @param subject the entity identifier of the entity to get the trust mark for
   * @param trustMarkType the trust mark identifier
   * @return the trust mark (a signed JWT of type {@code trust-mark+jwt})
   */
  @Nonnull
  public SignedJWT fetchTrustMark(@Nonnull final URI trustMarkEndpoint, @Nonnull final String subject,
      @Nonnull final String trustMarkType) {

    final URI url = UriComponentsBuilder.fromUri(trustMarkEndpoint)
        .queryParam("sub", subject)
        .queryParam("trust_mark_type", trustMarkType)
        .build()
        .encode()
        .toUri();
    log.debug("Fetching trust mark {} for {} from {}", trustMarkType, subject, url);

    final String response;
    try {
      response = this.getString(url);
    }
    catch (final RestClientResponseException e) {
      // The federation API reports errors as a JSON object holding error and error_description - include it.
      throw new IllegalArgumentException("The trust mark endpoint %s responded with %s: %s"
          .formatted(url, e.getStatusCode(), e.getResponseBodyAsString()), e);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to invoke the trust mark endpoint " + url, e);
    }
    try {
      return SignedJWT.parse(response);
    }
    catch (final java.text.ParseException e) {
      throw new IllegalArgumentException("The trust mark endpoint " + url + " did not return a signed JWT", e);
    }
  }

  /**
   * Downloads a JWK set from the given URI.
   *
   * @param jwksUri the JWK set URI
   * @return a {@link JWKSet}
   */
  @Nonnull
  public JWKSet fetchJwks(@Nonnull final URI jwksUri) {
    final JSONObject body = this.client.get().uri(jwksUri).retrieve().body(JSONObject.class);
    try {
      return JWKSet.parse(body);
    }
    catch (final java.text.ParseException e) {
      throw new IllegalArgumentException("Failed to parse JWK set from " + jwksUri, e);
    }
  }

  /**
   * Downloads a signed JWK set ({@code signed_jwks_uri}) and verifies its signature using the supplied keys.
   *
   * @param signedJwksUri the signed JWK set URI
   * @param verificationKeys the keys that the JWT is expected to be signed with (typically the entity's federation
   *     keys)
   * @return a {@link JWKSet}
   */
  @Nonnull
  public JWKSet fetchSignedJwks(@Nonnull final URI signedJwksUri, @Nonnull final JWKSet verificationKeys) {
    try {
      final SignedJWT jwt = SignedJWT.parse(this.getString(signedJwksUri));
      JwtVerifier.verify(jwt, verificationKeys);
      return JWKSet.parse(new JSONObject(jwt.getJWTClaimsSet().toJSONObject()));
    }
    catch (final BadJOSEException e) {
      throw new IllegalArgumentException("Signature validation of signed JWK set from " + signedJwksUri + " failed", e);
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Failed to get signed JWK set from " + signedJwksUri, e);
    }
  }

  @Nonnull
  private static String message(@Nonnull final Throwable e) {
    return Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName());
  }

  @Nonnull
  private String getString(@Nonnull final URI url) {
    final String body = this.client.get()
        .uri(url)
        .retrieve()
        .body(String.class);
    if (body == null || body.isBlank()) {
      throw new IllegalArgumentException("Empty response from " + url);
    }
    return body.trim();
  }

}
