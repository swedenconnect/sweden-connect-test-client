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
package se.swedenconnect.testclient.oidc.federation;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.api.ResolveClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.federation.trust.ResolveException;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.oidc.OidcOp;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for the "consumer side" of OpenID Federation - discovering OP:s using subordinate listings and configuring
 * them from the metadata handed out by the trust anchor.
 * <p>
 * The resolution is delegated to the trust anchor's resolve endpoint rather than performed locally. The trust anchor
 * knows its own subordinates and can therefore build the chain top-down, whereas a local resolver must walk it
 * bottom-up using {@code authority_hints} - something that fails as soon as an intermediate does not declare its
 * superiors. What we validate is the resolve response itself: it must be signed by the trust anchor, be issued about
 * the entity we asked for, and still be valid.
 * </p>
 *
 * @author Felix Hellman
 */
@Slf4j
public class OidfService {

  /** The federation settings. */
  private final OidfProperties properties;

  /** The federation HTTP client. */
  private final OidfClient client;

  /** Cached trust anchor keys. */
  private final Map<String, JWKSet> trustAnchorKeys = new ConcurrentHashMap<>();

  /** Cached resolve endpoints - one per trust anchor. */
  private final Map<String, URI> resolveEndpoints = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param properties the federation settings
   * @param client the federation HTTP client
   */
  public OidfService(@Nonnull final OidfProperties properties, @Nonnull final OidfClient client) {
    this.properties = properties;
    this.client = client;
  }

  /**
   * Gets the configured trust anchors.
   *
   * @return the trust anchor entity identifiers
   */
  @Nonnull
  public List<String> getTrustAnchors() {
    return this.properties.getTrustAnchors().stream()
        .map(OidfProperties.TrustAnchorProperties::getEntityId)
        .toList();
  }

  /**
   * Gets how often the federation is traversed in order to discover, and re-configure, OP:s.
   *
   * @return the refresh interval
   */
  @Nonnull
  public Duration getRefreshInterval() {
    return this.properties.getRefreshInterval();
  }

  /**
   * Gets the authorities that the subordinate listing endpoints are invoked against when discovering OP:s. Unless
   * the {@code subordinate-listing-sources} setting is used, this is the trust anchors themselves.
   *
   * @return the entity identifiers of the listing sources
   */
  @Nonnull
  public List<String> getSubordinateListingSources() {
    return this.getListingSources().stream()
        .map(ListingSource::entityId)
        .toList();
  }

  /**
   * Gets the authorities that the subordinate listing endpoints are invoked against when discovering OP:s, along with
   * the trust anchor that each of them belongs to (i.e., the anchor that its subordinates should be resolved under).
   * Unless the {@code subordinate-listing-sources} setting is used, this is the trust anchors themselves.
   *
   * @return the listing sources
   */
  @Nonnull
  public List<ListingSource> getListingSources() {
    final List<ListingSource> sources = new ArrayList<>();
    for (final OidfProperties.TrustAnchorProperties ta : this.properties.getTrustAnchors()) {
      if (!ta.isDiscoverOps()) {
        continue;
      }
      for (final OidfProperties.ListingSourceProperties source : ta.getDiscoverySources()) {
        final ListingSource listingSource = new ListingSource(source.getEntityId(), ta.getEntityId());
        if (!sources.contains(listingSource)) {
          sources.add(listingSource);
        }
      }
    }
    return sources;
  }

  /**
   * A configured authority to invoke subordinate listings against, and the trust anchor it was configured under.
   *
   * @param entityId the entity identifier of the authority
   * @param trustAnchor the entity identifier of the trust anchor
   */
  public record ListingSource(@Nonnull String entityId, @Nonnull String trustAnchor) {
  }

  /**
   * Discovers all OP:s that are subordinates (directly, or via intermediates) of the configured trust anchors, and
   * resolves each of them into a fully configured {@link OidcOp}.
   *
   * @return the result of the operation
   */
  @Nonnull
  public FederationRefreshResult refreshOps() {
    final List<OidcOp> ops = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    final Map<String, String> failures = new LinkedHashMap<>();

    for (final OidfProperties.TrustAnchorProperties ta : this.properties.getTrustAnchors()) {
      if (!ta.isDiscoverOps()) {
        continue;
      }
      final EntityID trustAnchor = new EntityID(ta.getEntityId());

      // The discovery normally starts at the trust anchor, but may be directed to one, or more, intermediates
      // using the subordinate-listing-sources setting.
      final Set<EntityID> discovered = new LinkedHashSet<>();
      final Set<EntityID> visited = new LinkedHashSet<>();
      for (final OidfProperties.ListingSourceProperties source : ta.getDiscoverySources()) {
        final EntityID listingSource = new EntityID(source.getEntityId());
        try {
          this.discoverOps(listingSource, source.getListEndpoint(), this.properties.getMaxListingDepth(),
              visited, discovered);
        }
        catch (final Exception e) {
          log.warn("Failed to list subordinates of {}", listingSource, e);
          errors.add("Subordinate listing failed for %s: %s".formatted(listingSource, message(e)));
        }
      }
      log.info("Discovered {} OpenID Provider(s) under trust anchor {} (listing source(s): {})",
          discovered.size(), trustAnchor, this.getSubordinateListingSources());

      for (final EntityID op : discovered) {
        try {
          ops.add(this.resolveOp(op, trustAnchor));
        }
        catch (final Exception e) {
          log.warn("Failed to resolve OpenID Provider {} under {}", op, trustAnchor, e);
          final String reason = message(e);
          errors.add("Resolution of %s failed: %s".formatted(op, reason));
          failures.put(op.getValue(), reason);
        }
      }
    }
    // An OP that was resolved under one trust anchor is not reported as failing because another one could not
    // resolve it.
    ops.forEach(op -> failures.remove(op.getEntityId()));
    return new FederationRefreshResult(ops, errors, failures);
  }

  /**
   * Lists the subordinates of the given authority.
   *
   * @param authority the authority (trust anchor or intermediate)
   * @param entityType optional entity type to filter on
   * @return the subordinate entity identifiers
   */
  @Nonnull
  public List<EntityID> listSubordinates(@Nonnull final EntityID authority, @Nullable final EntityType entityType) {
    final URI listEndpoint = Optional.ofNullable(this.configuredListEndpoint(authority))
        .orElseGet(() -> this.federationListEndpoint(authority));
    if (listEndpoint == null) {
      throw new IllegalArgumentException("%s does not publish a federation_list_endpoint".formatted(authority));
    }
    return this.client.listSubordinates(listEndpoint, entityType);
  }

  /**
   * Resolves the given OP against the trust anchor's resolve endpoint, resulting in a configured {@link OidcOp}.
   *
   * @param op the entity identifier of the OP
   * @param trustAnchor the trust anchor to resolve against
   * @return an {@link OidcOp}
   */
  @Nonnull
  public OidcOp resolveOp(@Nonnull final EntityID op, @Nonnull final EntityID trustAnchor) {
    final ResolveClaimsSet resolved = this.resolve(op, trustAnchor);

    final JSONObject metadata = resolved.getMetadata(EntityType.OPENID_PROVIDER);
    if (metadata == null) {
      throw new IllegalArgumentException(
          "The resolve response for %s does not contain openid_provider metadata".formatted(op));
    }
    return this.toOidcOp(op, trustAnchor, resolved, metadata);
  }

  /**
   * Gets the trust chain (as serialized JWT:s) for the given entity. The chain is the one reported by the trust
   * anchor in its resolve response.
   *
   * @param entity the entity identifier
   * @param trustAnchor the trust anchor to resolve against
   * @return the serialized trust chain, starting with the leaf entity configuration
   */
  @Nonnull
  public List<String> getTrustChain(@Nonnull final EntityID entity, @Nonnull final EntityID trustAnchor) {
    final TrustChain chain = this.resolve(entity, trustAnchor).getTrustChain();
    if (chain == null) {
      throw new IllegalArgumentException("The resolve response for %s under %s does not contain a trust chain"
          .formatted(entity, trustAnchor));
    }
    return chain.toSerializedJWTs();
  }

  /**
   * Invokes the resolve endpoint of the trust anchor and validates the response - it must be signed by the trust
   * anchor, be issued about the requested entity and not have expired.
   *
   * @param entity the entity to resolve
   * @param trustAnchor the trust anchor to resolve under
   * @return the claims of the resolve response
   */
  @Nonnull
  private ResolveClaimsSet resolve(@Nonnull final EntityID entity, @Nonnull final EntityID trustAnchor) {
    final SignedJWT jwt = this.client.resolve(this.resolveEndpointFor(trustAnchor), entity, trustAnchor, null);
    try {
      JwtVerifier.verify(jwt, this.getTrustAnchorKeys(trustAnchor));
    }
    catch (final BadJOSEException e) {
      throw new IllegalArgumentException(
          "Signature validation of the resolve response for %s under %s failed: %s"
              .formatted(entity, trustAnchor, message(e)), e);
    }

    final ResolveClaimsSet claims;
    try {
      claims = new ResolveClaimsSet(jwt.getJWTClaimsSet());
      claims.validateRequiredClaimsPresence();
    }
    catch (final Exception e) {
      throw new IllegalArgumentException(
          "Invalid resolve response for %s under %s: %s".formatted(entity, trustAnchor, message(e)), e);
    }

    if (!trustAnchor.equals(claims.getIssuerEntityID())) {
      throw new IllegalArgumentException("The resolve response for %s was issued by %s - expected %s"
          .formatted(entity, claims.getIssuerEntityID(), trustAnchor));
    }
    if (!entity.equals(claims.getSubjectEntityID())) {
      throw new IllegalArgumentException("The resolve response from %s is about %s - expected %s"
          .formatted(trustAnchor, claims.getSubjectEntityID(), entity));
    }
    final Date expirationTime = claims.getExpirationTime();
    if (expirationTime != null && expirationTime.before(new Date())) {
      throw new IllegalArgumentException("The resolve response for %s under %s expired at %s"
          .formatted(entity, trustAnchor, expirationTime.toInstant()));
    }
    return claims;
  }

  /**
   * Fetches the entity configuration of the given entity.
   *
   * @param entity the entity identifier
   * @return an {@link EntityStatement}
   */
  @Nonnull
  public EntityStatement fetchEntityConfiguration(@Nonnull final EntityID entity) {
    try {
      return this.client.fetchEntityConfiguration(entity);
    }
    catch (final ResolveException e) {
      throw new IllegalArgumentException(
          "Failed to fetch entity configuration for %s: %s".formatted(entity, message(e)), e);
    }
  }

  /**
   * Gets the authority to list subordinates of when nothing else is stated - the first configured listing source, or,
   * if no such source has been configured, the default trust anchor.
   *
   * @return the default listing authority
   */
  @Nonnull
  public EntityID getDefaultListingSource() {
    return this.getListingSources().stream()
        .findFirst()
        .map(source -> new EntityID(source.entityId()))
        .orElseGet(this::getDefaultTrustAnchor);
  }

  /**
   * Gets the trust anchor to use when nothing else is stated (the first configured one).
   *
   * @return the default trust anchor
   */
  @Nonnull
  public EntityID getDefaultTrustAnchor() {
    return this.properties.getTrustAnchors().stream()
        .findFirst()
        .map(ta -> new EntityID(ta.getEntityId()))
        .orElseThrow(() -> new IllegalArgumentException("No trust anchors have been configured"));
  }

  @Nonnull
  private OidcOp toOidcOp(@Nonnull final EntityID op, @Nonnull final EntityID trustAnchor,
      @Nonnull final ResolveClaimsSet resolved, @Nonnull final JSONObject metadata) {

    final TrustChain chain = resolved.getTrustChain();
    final String issuer = Optional.ofNullable(metadata.getAsString("issuer")).orElseGet(op::getValue);
    final String displayName = Optional.ofNullable(metadata.getAsString("organization_name"))
        .or(() -> Optional.ofNullable(resolved.getMetadata(EntityType.FEDERATION_ENTITY))
            .map(m -> m.getAsString("organization_name")))
        .or(() -> Optional.ofNullable(chain)
            .map(TrustChain::getLeafConfiguration)
            .map(leaf -> leaf.getClaimsSet().getFederationEntityMetadata())
            .map(FederationEntityMetadata::getOrganizationName))
        .orElse(issuer);

    return OidcOp.builder()
        .entityId(issuer)
        .displayName(displayName)
        .description("Resolved via OpenID Federation (trust anchor %s)".formatted(trustAnchor.getValue()))
        .authorizationEndpoint(metadata.getAsString("authorization_endpoint"))
        .tokenEndpoint(metadata.getAsString("token_endpoint"))
        .userInfoEndpoint(metadata.getAsString("userinfo_endpoint"))
        .metadataEndpoint(OidfClient.entityConfigurationUrl(op.getValue()))
        .source(OidcOp.Source.FEDERATION)
        .trustAnchor(trustAnchor.getValue())
        .trustChain(Optional.ofNullable(chain).map(TrustChain::toSerializedJWTs).orElseGet(List::of))
        .resolvedMetadata(metadata)
        .jwks(this.resolveJwks(op, metadata, chain))
        .expiresAt(Optional.ofNullable(resolved.getExpirationTime()).map(Date::toInstant).orElse(null))
        .build();
  }

  /**
   * Gets the OP signing/encryption keys - either inline in the metadata, from a signed JWK set, or from a JWK set
   * URI.
   */
  @Nullable
  private JWKSet resolveJwks(@Nonnull final EntityID op, @Nonnull final JSONObject metadata,
      @Nullable final TrustChain chain) {
    try {
      if (metadata.get("jwks") instanceof final Map<?, ?> jwks) {
        @SuppressWarnings("unchecked")
        final Map<String, Object> map = (Map<String, Object>) jwks;
        return JWKSet.parse(new JSONObject(map));
      }
      final String signedJwksUri = metadata.getAsString("signed_jwks_uri");
      if (signedJwksUri != null) {
        return this.client.fetchSignedJwks(URI.create(signedJwksUri), this.federationKeys(op, chain));
      }
      final String jwksUri = metadata.getAsString("jwks_uri");
      if (jwksUri != null) {
        return this.client.fetchJwks(URI.create(jwksUri));
      }
    }
    catch (final Exception e) {
      log.warn("Failed to get JWK set for {}", op, e);
    }
    return null;
  }

  /**
   * Gets the federation keys of an entity - the ones that a {@code signed_jwks_uri} is signed with. They are taken
   * from the leaf entity configuration of the resolved trust chain, and if the trust anchor did not report a chain,
   * from the entity configuration itself.
   */
  @Nonnull
  private JWKSet federationKeys(@Nonnull final EntityID op, @Nullable final TrustChain chain) {
    return Optional.ofNullable(chain)
        .map(TrustChain::getLeafConfiguration)
        .map(leaf -> leaf.getClaimsSet().getJWKSet())
        .orElseGet(() -> this.fetchEntityConfiguration(op).getClaimsSet().getJWKSet());
  }

  /**
   * Walks the federation tree below the given authority looking for entities that declare
   * {@code openid_provider} metadata.
   */
  private void discoverOps(@Nonnull final EntityID authority, @Nullable final URI endpointOverride,
      final int remainingDepth, @Nonnull final Set<EntityID> visited, @Nonnull final Set<EntityID> ops) {

    if (!visited.add(authority)) {
      return;
    }
    // The listing endpoint is normally read from the authority's entity configuration, but may be assigned
    // explicitly for the configured listing sources.
    final URI listEndpoint = endpointOverride != null ? endpointOverride : this.federationListEndpoint(authority);
    if (listEndpoint == null) {
      log.debug("{} does not publish a federation_list_endpoint - not traversing it", authority);
      return;
    }

    try {
      ops.addAll(this.client.listSubordinates(listEndpoint, EntityType.OPENID_PROVIDER));
    }
    catch (final Exception e) {
      log.debug("Listing of openid_provider subordinates of {} failed - falling back to a full listing", authority, e);
    }

    if (remainingDepth <= 0) {
      return;
    }
    for (final EntityID subordinate : this.client.listSubordinates(listEndpoint, null)) {
      if (ops.contains(subordinate) || visited.contains(subordinate)) {
        continue;
      }
      final EntityStatement configuration;
      try {
        configuration = this.client.fetchEntityConfiguration(subordinate);
      }
      catch (final Exception e) {
        log.debug("Failed to fetch entity configuration for subordinate {}", subordinate, e);
        continue;
      }
      if (configuration.getClaimsSet().getMetadata(EntityType.OPENID_PROVIDER) != null) {
        ops.add(subordinate);
        continue;
      }
      if (this.listEndpoint(configuration) != null) {
        this.discoverOps(subordinate, null, remainingDepth - 1, visited, ops);
      }
    }
  }

  /**
   * If the given authority is one of the configured listing sources, and that source has an explicitly assigned
   * listing endpoint, this endpoint is returned.
   *
   * @param authority the authority
   * @return the configured listing endpoint, or {@code null} if none has been assigned
   */
  @Nullable
  private URI configuredListEndpoint(@Nonnull final EntityID authority) {
    return this.properties.getTrustAnchors().stream()
        .map(OidfProperties.TrustAnchorProperties::getDiscoverySources)
        .flatMap(List::stream)
        .filter(s -> authority.getValue().equals(s.getEntityId()))
        .map(OidfProperties.ListingSourceProperties::getListEndpoint)
        .filter(Objects::nonNull)
        .findFirst()
        .orElse(null);
  }

  @Nullable
  private URI federationListEndpoint(@Nonnull final EntityID authority) {
    return this.listEndpoint(this.fetchEntityConfiguration(authority));
  }

  @Nullable
  private URI listEndpoint(@Nonnull final EntityStatement statement) {
    return Optional.ofNullable(statement.getClaimsSet().getFederationEntityMetadata())
        .map(FederationEntityMetadata::getFederationListEndpointURI)
        .orElse(null);
  }

  /**
   * Gets the resolve endpoint of a trust anchor - either the configured one, or the {@code federation_resolve_endpoint}
   * of its entity configuration.
   */
  @Nonnull
  private URI resolveEndpointFor(@Nonnull final EntityID trustAnchor) {
    return this.resolveEndpoints.computeIfAbsent(trustAnchor.getValue(), id -> {
      final URI configured = this.properties.getTrustAnchors().stream()
          .filter(ta -> Objects.equals(ta.getEntityId(), id))
          .map(OidfProperties.TrustAnchorProperties::getResolveEndpoint)
          .filter(Objects::nonNull)
          .findFirst()
          .orElse(null);
      if (configured != null) {
        return configured;
      }
      return Optional.ofNullable(
              this.fetchEntityConfiguration(trustAnchor).getClaimsSet().getFederationEntityMetadata())
          .map(FederationEntityMetadata::getFederationResolveEndpointURI)
          .orElseThrow(() -> new IllegalArgumentException(
              "%s does not publish a federation_resolve_endpoint".formatted(id)));
    });
  }

  /**
   * Gets the keys of a trust anchor. These are normally configured out-of-band, but if they are not, the trust
   * anchor's entity configuration is downloaded and its self-declared keys are used.
   */
  @Nonnull
  private JWKSet getTrustAnchorKeys(@Nonnull final EntityID trustAnchor) {
    return this.trustAnchorKeys.computeIfAbsent(trustAnchor.getValue(), id -> {
      final JWKSet configured = this.properties.getTrustAnchors().stream()
          .filter(ta -> Objects.equals(ta.getEntityId(), id))
          .map(OidfProperties.TrustAnchorProperties::getJwks)
          .filter(Objects::nonNull)
          .findFirst()
          .orElse(null);
      if (configured != null) {
        return configured;
      }
      log.warn("No JWK set configured for trust anchor {} - using the keys from its entity configuration. "
          + "This offers no protection against a rogue trust anchor and should only be used for testing", id);
      return this.fetchEntityConfiguration(trustAnchor).getClaimsSet().getJWKSet();
    });
  }

  @Nonnull
  private static String message(@Nonnull final Throwable e) {
    return Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName());
  }

  /**
   * The result of a federation refresh.
   *
   * @param ops the OP:s that were successfully resolved
   * @param errors the errors that occurred (if any)
   * @param failures the OP:s that were discovered but could not be resolved - entity identifier to reason
   */
  public record FederationRefreshResult(@Nonnull List<OidcOp> ops, @Nonnull List<String> errors,
                                        @Nonnull Map<String, String> failures) {
  }

}
