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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import se.swedenconnect.testclient.config.OidfProperties;
import se.swedenconnect.testclient.config.OidfProperties.TrustMarkProperties;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gets the trust marks that our RP:s publish in their entity configurations.
 * <p>
 * A trust mark is either configured with its value (a pre-issued trust mark JWT), or fetched from the trust mark
 * endpoint of its issuer. Fetched trust marks are validated - they must be signed by the issuer, be issued about the
 * RP, hold the requested trust mark type and not have expired - and are then cached until they expire (or at most
 * for the configured refresh interval).
 * </p>
 * <p>
 * Trust marks, and the entity configurations they are read from, are handled as {@link SignedJWT}:s rather than as
 * Nimbus OpenID Federation objects. The Nimbus federation types follow the drafts that preceded OpenID Federation
 * 1.0 (for example, they name the trust mark type claim {@code id}), and are therefore not used here.
 * </p>
 *
 * @author Felix Hellman
 */
@Slf4j
public class TrustMarkResolver {

  /** The JOSE object type of a trust mark. */
  public static final JOSEObjectType TRUST_MARK_TYPE_HEADER = new JOSEObjectType("trust-mark+jwt");

  /** The claim, and metadata parameter, naming the trust mark type. */
  public static final String TRUST_MARK_TYPE_CLAIM = "trust_mark_type";

  /** The name that the trust mark type has in the OpenID Federation drafts that preceded 1.0. */
  public static final String LEGACY_TRUST_MARK_TYPE_CLAIM = "id";

  /** The {@code federation_entity} metadata parameter holding the trust mark endpoint of an issuer. */
  public static final String TRUST_MARK_ENDPOINT_PARAMETER = "federation_trust_mark_endpoint";

  /** The entity type of the metadata that the trust mark endpoint is published in. */
  private static final String FEDERATION_ENTITY = "federation_entity";

  /** The federation settings. */
  private final OidfProperties properties;

  /** The federation HTTP client. */
  private final OidfClient client;

  /** The trust marks declared by the individual RP:s - keyed by the RP path suffix. */
  private final Map<String, List<TrustMarkProperties>> rpTrustMarks;

  /** Cached trust marks - keyed by RP entity identifier and trust mark type. */
  private final Map<String, CachedTrustMark> cache = new ConcurrentHashMap<>();

  /**
   * Constructor.
   *
   * @param properties the federation settings
   * @param client the federation HTTP client
   * @param rpTrustMarks the trust marks declared by the individual RP:s, keyed by RP path suffix (an RP that does
   *     not declare any trust marks of its own gets the ones from the federation settings)
   */
  public TrustMarkResolver(@Nonnull final OidfProperties properties, @Nonnull final OidfClient client,
      @Nonnull final Map<String, List<TrustMarkProperties>> rpTrustMarks) {
    this.properties = properties;
    this.client = client;
    this.rpTrustMarks = Map.copyOf(rpTrustMarks);
  }

  /**
   * Gets the trust marks of the supplied RP. Trust marks that could not be obtained are included in the result with
   * their error message - it is up to the caller to decide what to do about them.
   *
   * @param rp the Relying Party
   * @return the trust marks
   */
  @Nonnull
  public List<ResolvedTrustMark> resolve(@Nonnull final OidcRp rp) {
    final List<ResolvedTrustMark> trustMarks = new ArrayList<>();
    for (final TrustMarkProperties tm : this.trustMarksFor(rp)) {
      trustMarks.add(this.resolve(rp, tm));
    }
    return trustMarks;
  }

  /**
   * Discards all cached trust marks, meaning that they are fetched again the next time they are needed.
   */
  public void clearCache() {
    this.cache.clear();
  }

  /**
   * Gets the trust marks that the supplied RP should publish - its own, and if it does not declare any, the ones
   * from the federation settings.
   *
   * @param rp the Relying Party
   * @return the configured trust marks
   */
  @Nonnull
  public List<TrustMarkProperties> trustMarksFor(@Nonnull final OidcRp rp) {
    final List<TrustMarkProperties> declared = this.rpTrustMarks.get(rp.getPathSuffix());
    return declared != null && !declared.isEmpty() ? declared : this.properties.getTrustMarks();
  }

  @Nonnull
  private ResolvedTrustMark resolve(@Nonnull final OidcRp rp, @Nonnull final TrustMarkProperties tm) {
    final String cacheKey = rp.getEntityId() + "|" + tm.getTrustMarkType();
    final CachedTrustMark cached = this.cache.get(cacheKey);
    if (cached != null && Instant.now().isBefore(cached.refreshAt())) {
      return cached.trustMark();
    }
    final ResolvedTrustMark resolved = this.get(rp, tm);
    if (resolved.trustMark() == null) {
      // Nothing to cache - but keep a valid trust mark from an earlier round rather than dropping it because the
      // issuer was unavailable this time.
      if (cached != null && cached.trustMark().isValidAt(Instant.now())) {
        log.warn("Failed to refresh trust mark {} for {} - keeping the one we already have: {}",
            tm.getTrustMarkType(), rp.getEntityId(), resolved.error());
        return cached.trustMark();
      }
      return resolved;
    }
    this.cache.put(cacheKey, new CachedTrustMark(resolved, this.refreshTimeFor(resolved)));
    return resolved;
  }

  @Nonnull
  private ResolvedTrustMark get(@Nonnull final OidcRp rp, @Nonnull final TrustMarkProperties tm) {
    if (tm.getValue() != null && !tm.getValue().isBlank()) {
      try {
        return this.validate(rp, tm, SignedJWT.parse(tm.getValue().trim()), null);
      }
      catch (final ParseException e) {
        return ResolvedTrustMark.failed(tm, "The configured trust mark is not a signed JWT: " + e.getMessage());
      }
    }
    try {
      final SignedJWT issuerConfiguration = this.client.fetchSignedEntityConfiguration(tm.getIssuer());
      final URI endpoint = Optional.ofNullable(tm.getTrustMarkEndpoint())
          .orElseGet(() -> trustMarkEndpoint(issuerConfiguration));
      if (endpoint == null) {
        return ResolvedTrustMark.failed(tm,
            "%s does not publish a %s".formatted(tm.getIssuer(), TRUST_MARK_ENDPOINT_PARAMETER));
      }
      final SignedJWT trustMark =
          this.client.fetchTrustMark(endpoint, rp.getEntityId(), tm.getTrustMarkType());
      return this.validate(rp, tm, trustMark, federationKeys(issuerConfiguration));
    }
    catch (final Exception e) {
      return ResolvedTrustMark.failed(tm, "Failed to get trust mark %s for %s from %s: %s"
          .formatted(tm.getTrustMarkType(), rp.getEntityId(), tm.getIssuer(), message(e)));
    }
  }

  /**
   * Validates a trust mark - it must be of the requested type, be issued about the RP, not have expired, and, if the
   * issuer keys are known, be signed by the issuer.
   *
   * @param rp the Relying Party that the trust mark is about
   * @param tm the trust mark settings
   * @param trustMark the trust mark
   * @param issuerKeys the federation keys of the issuer, or {@code null} if the signature should not be checked
   *     (a trust mark that has been configured by value is trusted as it is)
   * @return the result
   */
  @Nonnull
  private ResolvedTrustMark validate(@Nonnull final OidcRp rp, @Nonnull final TrustMarkProperties tm,
      @Nonnull final SignedJWT trustMark, @Nullable final JWKSet issuerKeys) {

    final JOSEObjectType type = trustMark.getHeader().getType();
    if (type != null && !TRUST_MARK_TYPE_HEADER.equals(type)) {
      return ResolvedTrustMark.failed(tm, "The trust mark %s for %s is of type %s - expected %s"
          .formatted(tm.getTrustMarkType(), rp.getEntityId(), type, TRUST_MARK_TYPE_HEADER));
    }
    final JWTClaimsSet claims;
    try {
      claims = trustMark.getJWTClaimsSet();
    }
    catch (final ParseException e) {
      return ResolvedTrustMark.failed(tm,
          "Invalid trust mark %s: %s".formatted(tm.getTrustMarkType(), e.getMessage()));
    }
    // The trust mark type is named id in the OpenID Federation drafts that preceded 1.0 - accept both names.
    final String trustMarkType = Optional.ofNullable(claims.getClaim(TRUST_MARK_TYPE_CLAIM))
        .or(() -> Optional.ofNullable(claims.getClaim(LEGACY_TRUST_MARK_TYPE_CLAIM)))
        .map(Object::toString)
        .orElse(null);
    if (!tm.getTrustMarkType().equals(trustMarkType)) {
      return ResolvedTrustMark.failed(tm,
          "The trust mark received for %s is of the type %s - expected %s"
              .formatted(rp.getEntityId(), trustMarkType, tm.getTrustMarkType()));
    }
    if (!rp.getEntityId().equals(claims.getSubject())) {
      return ResolvedTrustMark.failed(tm, "The trust mark %s is issued about %s - expected %s"
          .formatted(tm.getTrustMarkType(), claims.getSubject(), rp.getEntityId()));
    }
    if (tm.getIssuer() != null && !tm.getIssuer().equals(claims.getIssuer())) {
      return ResolvedTrustMark.failed(tm, "The trust mark %s was issued by %s - expected %s"
          .formatted(tm.getTrustMarkType(), claims.getIssuer(), tm.getIssuer()));
    }
    final Instant expiresAt = Optional.ofNullable(claims.getExpirationTime()).map(Date::toInstant).orElse(null);
    if (expiresAt != null && expiresAt.isBefore(Instant.now())) {
      return ResolvedTrustMark.failed(tm,
          "The trust mark %s for %s expired at %s".formatted(tm.getTrustMarkType(), rp.getEntityId(), expiresAt));
    }
    if (issuerKeys != null) {
      try {
        JwtVerifier.verify(trustMark, issuerKeys);
      }
      catch (final BadJOSEException e) {
        return ResolvedTrustMark.failed(tm, "Signature validation of the trust mark %s from %s failed: %s"
            .formatted(tm.getTrustMarkType(), claims.getIssuer(), message(e)));
      }
    }
    log.debug("Got trust mark {} for {} (issuer: {}, expires: {})",
        tm.getTrustMarkType(), rp.getEntityId(), claims.getIssuer(), expiresAt);
    return new ResolvedTrustMark(
        tm.getTrustMarkType(), claims.getIssuer(), trustMark, expiresAt, tm.isRequired(), null);
  }

  /**
   * A trust mark is used until it expires, and at most for the configured refresh interval.
   */
  @Nonnull
  private Instant refreshTimeFor(@Nonnull final ResolvedTrustMark trustMark) {
    final Instant interval = Instant.now().plus(this.properties.getTrustMarkRefreshInterval());
    return Optional.ofNullable(trustMark.expiresAt())
        .filter(expiresAt -> expiresAt.isBefore(interval))
        .orElse(interval);
  }

  /**
   * Gets the trust mark endpoint from the {@code federation_entity} metadata of the issuer's entity configuration.
   *
   * @param issuerConfiguration the entity configuration of the trust mark issuer
   * @return the trust mark endpoint, or {@code null} if the issuer does not publish one
   */
  @Nullable
  private static URI trustMarkEndpoint(@Nonnull final SignedJWT issuerConfiguration) {
    return Optional.ofNullable(claimsOf(issuerConfiguration).getClaim("metadata"))
        .filter(Map.class::isInstance)
        .map(metadata -> ((Map<?, ?>) metadata).get(FEDERATION_ENTITY))
        .filter(Map.class::isInstance)
        .map(federationEntity -> ((Map<?, ?>) federationEntity).get(TRUST_MARK_ENDPOINT_PARAMETER))
        .map(Object::toString)
        .map(URI::create)
        .orElse(null);
  }

  /**
   * Gets the federation keys of an entity, i.e., the {@code jwks} claim of its entity configuration. These are the
   * keys that its trust marks are signed with.
   *
   * @param entityConfiguration the entity configuration
   * @return a {@link JWKSet}
   */
  @Nonnull
  private static JWKSet federationKeys(@Nonnull final SignedJWT entityConfiguration) {
    final Map<String, Object> jwks;
    try {
      jwks = claimsOf(entityConfiguration).getJSONObjectClaim("jwks");
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid jwks claim in the entity configuration", e);
    }
    if (jwks == null) {
      throw new IllegalArgumentException("The entity configuration does not contain a jwks claim");
    }
    try {
      return JWKSet.parse(jwks);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Failed to parse the keys of the entity configuration", e);
    }
  }

  @Nonnull
  private static JWTClaimsSet claimsOf(@Nonnull final SignedJWT jwt) {
    try {
      return jwt.getJWTClaimsSet();
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Failed to parse the claims of " + jwt.getHeader().getType(), e);
    }
  }

  @Nonnull
  private static String message(@Nonnull final Throwable e) {
    return Optional.ofNullable(e.getMessage()).orElseGet(() -> e.getClass().getSimpleName());
  }

  /**
   * A trust mark that we have (or failed to) obtain for one of our RP:s.
   *
   * @param trustMarkType the trust mark type
   * @param issuer the entity identifier of the issuer (of the trust mark we got)
   * @param trustMark the trust mark, or {@code null} if it could not be obtained
   * @param expiresAt when the trust mark expires (may be {@code null})
   * @param required whether the trust mark is required
   * @param error the reason why the trust mark could not be obtained, or {@code null} if it was
   */
  public record ResolvedTrustMark(@Nonnull String trustMarkType, @Nullable String issuer,
                                  @Nullable SignedJWT trustMark, @Nullable Instant expiresAt, boolean required,
                                  @Nullable String error) {

    /**
     * Creates a result for a trust mark that could not be obtained.
     *
     * @param tm the trust mark settings
     * @param error the reason
     * @return a {@link ResolvedTrustMark}
     */
    @Nonnull
    public static ResolvedTrustMark failed(@Nonnull final TrustMarkProperties tm, @Nonnull final String error) {
      log.warn("{}", error);
      return new ResolvedTrustMark(tm.getTrustMarkType(), tm.getIssuer(), null, null, tm.isRequired(), error);
    }

    /**
     * Predicate telling whether the trust mark was obtained and is valid at the given time.
     *
     * @param time the time to check against
     * @return {@code true} if the trust mark may be published
     */
    public boolean isValidAt(@Nonnull final Instant time) {
      return this.trustMark != null && (this.expiresAt == null || this.expiresAt.isAfter(time));
    }

    /**
     * Gets the trust mark as it is published in an entity configuration.
     * <p>
     * The entry holds the trust mark type both as {@code trust_mark_type} (OpenID Federation 1.0) and as {@code id}
     * (the drafts that preceded it). The relying parties of the Sweden Connect federation services are read with
     * the Nimbus {@code TrustMarkEntry}, which requires {@code id}, whereas the trust marks themselves, and the
     * resolve responses, use {@code trust_mark_type} - so both names are needed to be understood by all of them.
     * </p>
     *
     * @return the trust mark entry as a JSON object
     */
    @Nonnull
    public JSONObject toJSONObject() {
      if (this.trustMark == null) {
        throw new IllegalStateException("The trust mark %s was not obtained".formatted(this.trustMarkType));
      }
      final JSONObject entry = new JSONObject();
      entry.put(TRUST_MARK_TYPE_CLAIM, this.trustMarkType);
      entry.put(LEGACY_TRUST_MARK_TYPE_CLAIM, this.trustMarkType);
      entry.put("trust_mark", this.trustMark.serialize());
      return entry;
    }
  }

  /**
   * A cached trust mark.
   *
   * @param trustMark the trust mark
   * @param refreshAt when it should be fetched again
   */
  private record CachedTrustMark(@Nonnull ResolvedTrustMark trustMark, @Nonnull Instant refreshAt) {
  }

}
