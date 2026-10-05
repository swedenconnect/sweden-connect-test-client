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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Creates (and caches) the OpenID Federation entity configurations that the test client publishes for its Relying
 * Parties.
 *
 * @author Felix Hellman
 */
@Slf4j
public class EntityConfigurationFactory {

  /** The federation settings. */
  private final OidfProperties properties;

  /** The immediate superiors of our RP:s. */
  private final List<EntityID> authorityHints;

  /** The resolver getting the trust marks that our RP:s publish (null if no trust marks are configured). */
  private final TrustMarkResolver trustMarkResolver;

  /** Cached entity configurations - one per RP. */
  private final Map<String, CachedConfiguration> cache = new ConcurrentHashMap<>();

  /** Signers - one per RP. */
  private final Map<String, OidfSigner> signers = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param properties the federation settings
   * @param authorityHints the immediate superiors of our RP:s
   * @param trustMarkResolver the resolver getting the trust marks to publish (may be {@code null})
   */
  public EntityConfigurationFactory(@Nonnull final OidfProperties properties,
      @Nonnull final List<EntityID> authorityHints,
      @Nullable final TrustMarkResolver trustMarkResolver) {
    this.properties = properties;
    this.authorityHints = authorityHints;
    this.trustMarkResolver = trustMarkResolver;
  }

  /**
   * Gets the entity configuration for the supplied RP. A cached statement is returned as long as it has not passed
   * half its validity time and holds the trust marks that the RP currently has. When a trust mark is obtained,
   * renewed or expires, the entity configuration is signed again.
   *
   * @param rp the Relying Party
   * @return an {@link EntityStatement}
   * @throws IllegalArgumentException if no entity configuration is set up for the RP
   */
  @Nonnull
  public EntityStatement getEntityConfiguration(@Nonnull final OidcRp rp) {
    assertHasEntityConfiguration(rp);
    final List<TrustMarkResolver.ResolvedTrustMark> trustMarks = this.getTrustMarks(rp);
    final List<String> published = publishable(trustMarks, this.now());
    final CachedConfiguration cached = this.cache.get(rp.getEntityId());
    if (cached != null && this.now().isBefore(cached.renewAt()) && cached.trustMarks().equals(published)) {
      return cached.statement();
    }
    final EntityStatement statement = this.createEntityConfiguration(rp, trustMarks);
    this.cache.put(rp.getEntityId(), new CachedConfiguration(statement, this.renewalTimeFor(statement), published));
    return statement;
  }

  /**
   * Fetches the trust marks of the supplied RP:s again and signs their entity configurations anew. A trust mark
   * that an RP already holds is kept if it can not be renewed. RP:s that have no entity configuration are ignored.
   *
   * @param rps the Relying Parties
   */
  public void refresh(@Nonnull final List<OidcRp> rps) {
    for (final OidcRp rp : rps) {
      if (!rp.hasEntityConfiguration()) {
        continue;
      }
      if (this.trustMarkResolver != null) {
        this.trustMarkResolver.refresh(rp);
      }
      this.cache.remove(rp.getEntityId());
      try {
        this.getEntityConfiguration(rp);
      }
      catch (final IllegalArgumentException e) {
        // The reason (a missing required trust mark) has already been logged when the trust mark was fetched.
        log.debug("No entity configuration created for {}: {}", rp.getEntityId(), e.getMessage());
      }
    }
  }

  /**
   * Gets the trust marks of the supplied RP - the ones we publish, and the ones we failed to get. An RP that has no
   * entity configuration has no trust marks.
   *
   * @param rp the Relying Party
   * @return the trust marks
   */
  @Nonnull
  public List<TrustMarkResolver.ResolvedTrustMark> getTrustMarks(@Nonnull final OidcRp rp) {
    return this.trustMarkResolver != null ? this.trustMarkResolver.resolve(rp) : List.of();
  }

  /**
   * Gets the signer that is used for the supplied RP's federation statements.
   *
   * @param rp the Relying Party
   * @return an {@link OidfSigner}
   */
  @Nonnull
  public OidfSigner getSigner(@Nonnull final OidcRp rp) {
    return this.signers.computeIfAbsent(rp.getEntityId(),
        id -> new OidfSigner(rp.getCredentials().getCredentialForMetadataSigning()));
  }

  /**
   * Creates a freshly signed entity configuration for the supplied RP.
   *
   * @param rp the Relying Party
   * @return an {@link EntityStatement}
   * @throws IllegalArgumentException if no entity configuration is set up for the RP
   */
  @Nonnull
  public EntityStatement createEntityConfiguration(@Nonnull final OidcRp rp) {
    assertHasEntityConfiguration(rp);
    return this.createEntityConfiguration(rp, this.getTrustMarks(rp));
  }

  /**
   * Creates a freshly signed entity configuration for the supplied RP holding the supplied trust marks.
   *
   * @param rp the Relying Party
   * @param trustMarks the trust marks of the RP
   * @return an {@link EntityStatement}
   */
  @Nonnull
  private EntityStatement createEntityConfiguration(@Nonnull final OidcRp rp,
      @Nonnull final List<TrustMarkResolver.ResolvedTrustMark> trustMarks) {
    final OidfSigner signer = this.getSigner(rp);
    final Instant issuedAt = this.now();
    final Instant expiresAt = issuedAt.plus(this.properties.getEntityConfigurationValidity());

    final EntityID entityId = new EntityID(rp.getEntityId());
    final EntityStatementClaimsSet claims = new EntityStatementClaimsSet(
        entityId, entityId, Date.from(issuedAt), Date.from(expiresAt), signer.getJwkSet());

    if (!this.authorityHints.isEmpty()) {
      claims.setAuthorityHints(this.authorityHints);
    }
    claims.setMetadata(EntityType.OPENID_RELYING_PARTY, this.rpMetadata(rp));
    this.assignTrustMarks(claims, rp, trustMarks);
    Optional.ofNullable(this.federationEntityMetadata()).ifPresent(claims::setFederationEntityMetadata);

    try {
      final EntityStatement statement =
          EntityStatement.parse(signer.sign(claims.toJWTClaimsSet(), EntityStatement.JOSE_OBJECT_TYPE));
      log.debug("Created entity configuration for {} (expires {})", rp.getEntityId(), expiresAt);
      return statement;
    }
    catch (final JOSEException | com.nimbusds.oauth2.sdk.ParseException e) {
      throw new IllegalArgumentException("Failed to create entity configuration for " + rp.getEntityId(), e);
    }
  }

  /**
   * Makes sure that an entity configuration is set up for the supplied RP.
   *
   * @param rp the Relying Party
   * @throws IllegalArgumentException if the RP has no entity configuration
   */
  private static void assertHasEntityConfiguration(@Nonnull final OidcRp rp) {
    if (!rp.hasEntityConfiguration()) {
      throw new IllegalArgumentException("The RP %s has no Entity Configuration".formatted(rp.getEntityId()));
    }
  }

  /**
   * Adds the {@code trust_marks} claim - the trust marks that the RP has been issued.
   *
   * @param claims the claims of the entity configuration
   * @param rp the Relying Party
   * @param trustMarks the trust marks of the RP
   */
  private void assignTrustMarks(@Nonnull final EntityStatementClaimsSet claims, @Nonnull final OidcRp rp,
      @Nonnull final List<TrustMarkResolver.ResolvedTrustMark> trustMarks) {
    if (trustMarks.isEmpty()) {
      return;
    }
    final Instant now = this.now();
    final JSONArray entries = new JSONArray();
    for (final TrustMarkResolver.ResolvedTrustMark trustMark : trustMarks) {
      if (trustMark.isValidAt(now)) {
        entries.add(trustMark.toJSONObject());
      }
      else if (trustMark.required()) {
        throw new IllegalArgumentException(
            "The required trust mark %s could not be obtained for %s: %s".formatted(
                trustMark.trustMarkType(), rp.getEntityId(), trustMark.error()));
      }
      else {
        // The reason has already been logged when the trust mark was fetched.
        log.debug("Publishing the entity configuration for {} without the trust mark {}",
            rp.getEntityId(), trustMark.trustMarkType());
      }
    }
    if (!entries.isEmpty()) {
      claims.setClaim("trust_marks", entries);
    }
  }

  /**
   * Builds the {@code openid_relying_party} metadata to publish.
   *
   * @param rp the Relying Party
   * @return the metadata as a JSON object
   */
  @Nonnull
  private JSONObject rpMetadata(@Nonnull final OidcRp rp) {
    final JSONObject metadata = new JSONObject(rp.getMetadata().toJSONObject(true));
    if (!metadata.containsKey("client_registration_types")
        && !this.properties.getClientRegistrationTypes().isEmpty()) {
      final JSONArray types = new JSONArray();
      types.addAll(this.properties.getClientRegistrationTypes());
      metadata.put("client_registration_types", types);
    }
    // The fields below are mandatory in the Sweden Connect federation. Unless an RP declares them itself, they are
    // filled in from the federation settings.
    if (!metadata.containsKey("subject_type")) {
      metadata.put("subject_type", this.properties.getSubjectType());
    }
    if (!metadata.containsKey("organization_number")) {
      metadata.put("organization_number", this.properties.getOrganizationNumber());
    }
    return metadata;
  }

  /**
   * Builds the {@code federation_entity} metadata to publish (if configured).
   *
   * @return the metadata, or {@code null} if nothing is configured
   */
  private FederationEntityMetadata federationEntityMetadata() {
    final OidfProperties.FederationEntityMetadataProperties p = this.properties.getEntityMetadata();
    if (p == null) {
      return null;
    }
    final FederationEntityMetadata metadata = new FederationEntityMetadata();
    metadata.setOrganizationName(p.getOrganizationName());
    if (p.getContacts() != null && !p.getContacts().isEmpty()) {
      metadata.setContacts(p.getContacts());
    }
    Optional.ofNullable(p.getHomepageUri()).map(URI::create).ifPresent(metadata::setHomepageURI);
    Optional.ofNullable(p.getPolicyUri()).map(URI::create).ifPresent(metadata::setPolicyURI);
    Optional.ofNullable(p.getLogoUri()).map(URI::create).ifPresent(metadata::setLogoURI);

    return metadata.toJSONObject().isEmpty() ? null : metadata;
  }

  /**
   * Calculates when an entity configuration should be created anew - when it has passed half its validity time.
   * Changes to the trust marks are detected when the entity configuration is asked for (see
   * {@link #getEntityConfiguration(OidcRp)}).
   *
   * @param statement the entity configuration
   * @return the time when it should be renewed
   */
  @Nonnull
  private Instant renewalTimeFor(@Nonnull final EntityStatement statement) {
    final Date expirationTime = statement.getClaimsSet().getExpirationTime();
    if (expirationTime == null) {
      return this.now();
    }
    return expirationTime.toInstant().minus(this.properties.getEntityConfigurationValidity().dividedBy(2));
  }

  /**
   * Gets the trust marks that are published, i.e., the ones that are valid at the given time.
   *
   * @param trustMarks the trust marks of an RP
   * @param now the current time
   * @return the serialized trust marks that are published
   */
  @Nonnull
  private static List<String> publishable(@Nonnull final List<TrustMarkResolver.ResolvedTrustMark> trustMarks,
      @Nonnull final Instant now) {
    return trustMarks.stream()
        .filter(tm -> tm.isValidAt(now))
        .map(tm -> tm.trustMark().serialize())
        .toList();
  }

  /**
   * Gets the current time - from the clock of the trust mark resolver, if there is one.
   *
   * @return the current time
   */
  @Nonnull
  private Instant now() {
    return this.trustMarkResolver != null ? this.trustMarkResolver.getClock().instant() : Instant.now();
  }

  /**
   * A cached entity configuration.
   *
   * @param statement the entity configuration
   * @param renewAt when it should be created anew
   * @param trustMarks the serialized trust marks that it holds
   */
  private record CachedConfiguration(@Nonnull EntityStatement statement, @Nonnull Instant renewAt,
      @Nonnull List<String> trustMarks) {
  }

}
