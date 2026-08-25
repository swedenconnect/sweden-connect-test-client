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
package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcOpRegistry;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.oidc.federation.EntityConfigurationFactory;
import se.swedenconnect.testclient.oidc.federation.OidfClient;
import se.swedenconnect.testclient.oidc.federation.OidfOpRefresher;
import se.swedenconnect.testclient.oidc.federation.OidfService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST controller for the OpenID Federation features - entity configuration publishing, subordinate listings and
 * trust chain resolution.
 *
 * @author Felix Hellman
 */
@Slf4j
@RestController
@RequestMapping("/oidc/federation")
@ConditionalOnProperty(value = "testclient.oidc.federation.enabled", havingValue = "true")
public class OidfRestController {

  /** The federation service. */
  private final OidfService federationService;

  /** The OP registry. */
  private final OidcOpRegistry opRegistry;

  /** The entity configuration factory. */
  private final EntityConfigurationFactory entityConfigurationFactory;

  /** The OIDC RP:s. */
  private final List<OidcRp> rps;

  /** The refresher (not present if auto-configuration has been turned off). */
  private final ObjectProvider<OidfOpRefresher> refresher;

  /**
   * Constructor.
   *
   * @param federationService the federation service
   * @param opRegistry the OP registry
   * @param entityConfigurationFactory the entity configuration factory
   * @param rps the OIDC RP:s
   * @param refresher the OP refresher
   */
  public OidfRestController(@Nonnull final OidfService federationService,
      @Nonnull final OidcOpRegistry opRegistry,
      @Nonnull final EntityConfigurationFactory entityConfigurationFactory,
      @Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> rps,
      @Nonnull final ObjectProvider<OidfOpRefresher> refresher) {
    this.federationService = federationService;
    this.opRegistry = opRegistry;
    this.entityConfigurationFactory = entityConfigurationFactory;
    this.rps = rps;
    this.refresher = refresher;
  }

  /**
   * Gets information about the federation setup - our own entities and the trust anchors, along with the result of
   * the latest refresh.
   *
   * @return a {@link FederationInfoModel}
   */
  @GetMapping(value = "/info", produces = MediaType.APPLICATION_JSON_VALUE)
  public FederationInfoModel getInfo() {
    return FederationInfoModel.builder()
        .trustAnchors(this.federationService.getTrustAnchors())
        .listingSources(this.federationService.getListingSources().stream()
            .map(s -> new ListingSourceModel(s.entityId(), s.trustAnchor()))
            .toList())
        .entities(this.rps.stream()
            .map(rp -> new FederationEntityModel(rp.getEntityId(), rp.getDescription(),
                OidfClient.entityConfigurationUrl(rp.getEntityId()), this.trustMarks(rp)))
            .toList())
        .lastRefresh(this.opRegistry.getLastFederationRefresh())
        .refreshInterval(this.federationService.getRefreshInterval().toSeconds())
        .errors(this.opRegistry.getFederationErrors())
        .providers(this.providers())
        .build();
  }

  /**
   * The status of every OP that has been discovered from the federation. An OP that has once been configured is
   * reported also when the latest refresh did not find it - it is still usable, but its status says that it is not
   * up to date.
   *
   * @return the providers
   */
  @Nonnull
  private List<OpenIdProviderModel> providers() {
    final Map<String, OidcOp> ops = this.opRegistry.getFederationOps().stream()
        .collect(Collectors.toMap(OidcOp::getEntityId, op -> op, (a, b) -> a));
    return this.opRegistry.getFederationOpStatuses().stream()
        .map(status -> toModel(ops.get(status.entityId()), status))
        .toList();
  }

  /**
   * Re-runs the discovery and resolution of the federation OP:s.
   *
   * @return a {@link FederationInfoModel}
   */
  @PostMapping(value = "/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
  public FederationInfoModel refresh() {
    final OidfOpRefresher opRefresher = this.refresher.getIfAvailable();
    if (opRefresher != null) {
      opRefresher.refresh();
    }
    else {
      final OidfService.FederationRefreshResult result = this.federationService.refreshOps();
      this.opRegistry.updateFederationOps(result.ops(), result.failures(), result.errors());
    }
    return this.getInfo();
  }

  /**
   * Discards the cached trust marks and entity configurations, meaning that the trust marks are fetched from their
   * issuers again.
   *
   * @return a {@link FederationInfoModel}
   */
  @PostMapping(value = "/trust-marks/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
  public FederationInfoModel refreshTrustMarks() {
    this.entityConfigurationFactory.clearCache();
    return this.getInfo();
  }

  /**
   * Gets the trust chain of an entity.
   *
   * @param entityId the entity identifier
   * @param trustAnchor the trust anchor to resolve under (defaults to the first configured trust anchor)
   * @return the trust chain, both serialized and decoded
   */
  @GetMapping(value = "/chain", produces = MediaType.APPLICATION_JSON_VALUE)
  public TrustChainModel getTrustChain(
      @RequestParam("entity_id") @Nonnull final String entityId,
      @RequestParam(value = "trust_anchor", required = false) @Nullable final String trustAnchor) {

    final EntityID anchor = Optional.ofNullable(trustAnchor)
        .map(EntityID::new)
        .orElseGet(this.federationService::getDefaultTrustAnchor);

    final List<String> chain = this.federationService.getTrustChain(new EntityID(entityId), anchor);
    return new TrustChainModel(entityId, anchor.getValue(), chain, claimsOfChain(chain));
  }

  /**
   * Gets the entity configuration of an entity - either one of ours (which is then created and signed) or a remote
   * one (which is downloaded).
   *
   * @param entityId the entity identifier
   * @return the entity statement, both serialized and decoded
   */
  @GetMapping(value = "/entity-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
  public EntityConfigurationModel getEntityConfiguration(@RequestParam("entity_id") @Nonnull final String entityId) {
    final String statement = this.rps.stream()
        .filter(rp -> entityId.equals(rp.getEntityId()))
        .findFirst()
        .map(rp -> this.entityConfigurationFactory.getEntityConfiguration(rp).getSignedStatement().serialize())
        .orElseGet(() -> this.federationService.fetchEntityConfiguration(new EntityID(entityId))
            .getSignedStatement()
            .serialize());

    return new EntityConfigurationModel(entityId, statement, claims(statement));
  }

  /**
   * Federation operations fail for all sorts of reasons (the entity is not part of the federation, the metadata
   * policy could not be applied, a signature did not validate, ...). Report these as bad requests along with the
   * reason, so that the user gets something to work with.
   *
   * @param e the error
   * @return an error model
   */
  @ExceptionHandler(IllegalArgumentException.class)
  @ResponseStatus(HttpStatus.BAD_REQUEST)
  public ErrorModel handleError(@Nonnull final IllegalArgumentException e) {
    log.info("OpenID Federation operation failed: {}", e.getMessage());
    return new ErrorModel("federation_error", e.getMessage());
  }

  @Nonnull
  private List<TrustMarkModel> trustMarks(@Nonnull final OidcRp rp) {
    return this.entityConfigurationFactory.getTrustMarks(rp).stream()
        .map(tm -> new TrustMarkModel(tm.trustMarkType(), tm.issuer(), tm.expiresAt(), tm.trustMark() != null,
            tm.error()))
        .toList();
  }

  @Nonnull
  private static List<Map<String, Object>> claimsOfChain(@Nullable final List<String> chain) {
    if (chain == null) {
      return List.of();
    }
    final List<Map<String, Object>> claims = new ArrayList<>();
    chain.stream().map(OidfRestController::claims).filter(Objects::nonNull).forEach(claims::add);
    return claims;
  }

  @Nullable
  private static Map<String, Object> claims(@Nonnull final String serializedJwt) {
    try {
      return SignedJWT.parse(serializedJwt).getJWTClaimsSet().toJSONObject();
    }
    catch (final java.text.ParseException e) {
      log.warn("Failed to parse entity statement", e);
      return null;
    }
  }

  /**
   * Builds the model for a federation OP. The OP is {@code null} if it has never been successfully resolved - all
   * that we know about it is then its status.
   */
  @Nonnull
  private static OpenIdProviderModel toModel(@Nullable final OidcOp op,
      @Nonnull final OidcOpRegistry.FederationOpStatus status) {

    final OpenIdProviderModel.OpenIdProviderModelBuilder builder = OpenIdProviderModel.builder()
        .entityId(status.entityId())
        .entityConfigurationUrl(OidfClient.entityConfigurationUrl(status.entityId()))
        .status(status.state().name().toLowerCase())
        .firstSeen(status.firstSeen())
        .lastResolved(status.lastResolved())
        .lastAttempt(status.lastAttempt())
        .error(status.error())
        .configured(op != null);

    if (op != null) {
      builder.displayName(op.getDisplayName())
          .description(op.getDescription())
          .trustAnchor(op.getTrustAnchor())
          .authorizationEndpoint(op.getAuthorizationEndpoint())
          .tokenEndpoint(op.getTokenEndpoint())
          .userInfoEndpoint(op.getUserInfoEndpoint())
          .expiresAt(op.getExpiresAt());
    }
    return builder.build();
  }

  /**
   * Model for errors.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ErrorModel {

    private String error;

    private String message;
  }

  /**
   * Model for general federation information.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class FederationInfoModel {

    @JsonProperty("trust_anchors")
    private List<String> trustAnchors;

    /** The authorities that are invoked when discovering OP:s. */
    @JsonProperty("listing_sources")
    private List<ListingSourceModel> listingSources;

    /** Our own federation entities. */
    private List<FederationEntityModel> entities;

    /** The OP:s that have been configured using the federation. */
    private List<OpenIdProviderModel> providers;

    @JsonProperty("last_refresh")
    private Instant lastRefresh;

    /** How often the federation is traversed in order to discover, and re-configure, OP:s - in seconds. */
    @JsonProperty("refresh_interval")
    private Long refreshInterval;

    private List<String> errors;
  }

  /**
   * Model for an authority whose subordinate listing endpoint is invoked when discovering OP:s.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ListingSourceModel {

    /** The entity identifier of the authority (a trust anchor or an intermediate). */
    @JsonProperty("entity_id")
    private String entityId;

    /** The trust anchor that the authority was configured under - subordinates are resolved under this anchor. */
    @JsonProperty("trust_anchor")
    private String trustAnchor;
  }

  /**
   * Model for one of our own federation entities.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class FederationEntityModel {

    @JsonProperty("entity_id")
    private String entityId;

    private String description;

    @JsonProperty("entity_configuration_url")
    private String entityConfigurationUrl;

    /** The trust marks that the entity publishes (including the ones that could not be obtained). */
    @JsonProperty("trust_marks")
    private List<TrustMarkModel> trustMarks;
  }

  /**
   * Model for a trust mark of one of our own federation entities.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class TrustMarkModel {

    /** The trust mark type, i.e., the identifier of the trust mark. */
    @JsonProperty("trust_mark_type")
    private String trustMarkType;

    /** The entity identifier of the trust mark issuer. */
    private String issuer;

    /** When the trust mark expires. */
    @JsonProperty("expires_at")
    private Instant expiresAt;

    /** Whether the trust mark was obtained and is published. */
    private boolean published;

    /** The reason why the trust mark could not be obtained. */
    private String error;
  }

  /**
   * Model for an OP that has been configured using the federation.
   */
  @Data
  @Builder
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class OpenIdProviderModel {

    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("display_name")
    private String displayName;

    private String description;

    @JsonProperty("trust_anchor")
    private String trustAnchor;

    @JsonProperty("entity_configuration_url")
    private String entityConfigurationUrl;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("userinfo_endpoint")
    private String userInfoEndpoint;

    @JsonProperty("expires_at")
    private Instant expiresAt;

    /** The state of the OP - {@code ok}, {@code error} or {@code not_listed}. */
    private String status;

    /** Whether the OP is configured, i.e., whether it may be used for authentication requests. */
    private boolean configured;

    /** When the OP was first discovered. */
    @JsonProperty("first_seen")
    private Instant firstSeen;

    /** When the OP was last successfully resolved. */
    @JsonProperty("last_resolved")
    private Instant lastResolved;

    /** When the OP was last part of a refresh. */
    @JsonProperty("last_attempt")
    private Instant lastAttempt;

    /** The reason why the OP could not be resolved during the latest refresh. */
    private String error;
  }

  /**
   * Model for a trust chain.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class TrustChainModel {

    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("trust_anchor")
    private String trustAnchor;

    private List<String> chain;

    @JsonProperty("chain_claims")
    private List<Map<String, Object>> chainClaims;
  }

  /**
   * Model for an entity configuration.
   */
  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class EntityConfigurationModel {

    @JsonProperty("entity_id")
    private String entityId;

    @JsonProperty("entity_statement")
    private String entityStatement;

    private Map<String, Object> claims;
  }

}
