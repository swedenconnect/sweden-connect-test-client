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
package se.swedenconnect.testclient.config;

import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Configuration properties for OpenID Federation (OIDF) support.
 *
 * @author Felix Hellman
 */
public class OidfProperties implements InitializingBean {

  /** The format of a Swedish organization number - ten digits without hyphen. */
  private static final Pattern ORGANIZATION_NUMBER_PATTERN = Pattern.compile("^\\d{10}$");

  /**
   * Whether OpenID Federation support is enabled.
   */
  @Getter
  @Setter
  private boolean enabled = false;

  /**
   * The trust anchors of the federation(s) that we participate in.
   */
  @Getter
  @NestedConfigurationProperty
  private final List<TrustAnchorProperties> trustAnchors = new ArrayList<>();

  /**
   * Whether OP:s should be discovered automatically (using subordinate listings) and configured (using the resolve
   * endpoints of the trust anchors).
   */
  @Getter
  @Setter
  private boolean autoConfigureOps = true;

  /**
   * How often the federation should be traversed in order to discover, and re-configure, OP:s.
   */
  @Getter
  @Setter
  private Duration refreshInterval = Duration.ofMinutes(10);

  /**
   * The validity of the entity configurations that we publish.
   */
  @Getter
  @Setter
  private Duration entityConfigurationValidity = Duration.ofHours(24);

  /**
   * The maximum number of intermediate levels that are traversed when listing subordinates.
   */
  @Getter
  @Setter
  private int maxListingDepth = 5;

  /**
   * The {@code client_registration_types} to declare in our published RP metadata.
   */
  @Getter
  @Setter
  private List<String> clientRegistrationTypes = List.of("automatic");

  /**
   * The Swedish organization number of the organization owning the RP:s. Published as
   * {@code organization_number} in the RP metadata (unless the RP declares its own). Exactly ten digits, no
   * hyphen.
   */
  @Getter
  @Setter
  private String organizationNumber;

  /**
   * The path, relative to the application base URL, to the logotype to publish as {@code logo_uri} in the RP
   * metadata (unless the RP declares its own). The logotype must be served from the same host as the RP entity
   * identifiers, which is why it is given as a path within this application.
   */
  @Getter
  @Setter
  private String logoPath = "/images/logo.svg";

  /**
   * The {@code subject_type} to declare in our published RP metadata (unless the RP declares its own).
   */
  @Getter
  @Setter
  private String subjectType = "pairwise";

  /**
   * The {@code federation_entity} metadata to include in the published entity configurations.
   */
  @Getter
  @Setter
  @NestedConfigurationProperty
  private FederationEntityMetadataProperties entityMetadata = new FederationEntityMetadataProperties();

  /**
   * The trust marks that all published RP entity configurations should contain. A trust mark is either configured
   * with its value (a pre-issued trust mark JWT), or fetched from the trust mark endpoint of its issuer. An RP may
   * declare its own set of trust marks, and in that case, this list is not used for that RP.
   */
  @Getter
  @NestedConfigurationProperty
  private final List<TrustMarkProperties> trustMarks = new ArrayList<>();

  /**
   * How long a fetched trust mark is used before it is fetched again. A trust mark that expires before this
   * interval has passed is re-fetched when it expires.
   */
  @Getter
  @Setter
  private Duration trustMarkRefreshInterval = Duration.ofHours(1);

  @Override
  public void afterPropertiesSet() {
    if (this.enabled) {
      Assert.notEmpty(this.trustAnchors, "testclient.oidc.federation.trust-anchors must be set");
      this.trustAnchors.forEach(TrustAnchorProperties::afterPropertiesSet);
      Assert.notNull(this.refreshInterval, "testclient.oidc.federation.refresh-interval must be set");
      Assert.notNull(this.entityConfigurationValidity,
          "testclient.oidc.federation.entity-configuration-validity must be set");
      Assert.hasText(this.organizationNumber, "testclient.oidc.federation.organization-number must be set");
      Assert.isTrue(ORGANIZATION_NUMBER_PATTERN.matcher(this.organizationNumber).matches(),
          "testclient.oidc.federation.organization-number must be exactly ten digits");
      Assert.hasText(this.logoPath, "testclient.oidc.federation.logo-path must be set");
      Assert.hasText(this.subjectType, "testclient.oidc.federation.subject-type must be set");
      this.trustMarks.forEach(TrustMarkProperties::afterPropertiesSet);
      Assert.notNull(this.trustMarkRefreshInterval,
          "testclient.oidc.federation.trust-mark-refresh-interval must be set");
    }
  }

  /**
   * Properties for a federation trust anchor.
   */
  public static class TrustAnchorProperties implements InitializingBean {

    /**
     * The entity identifier of the trust anchor.
     */
    @Getter
    @Setter
    private String entityId;

    /**
     * The trust anchor JWK set. This key set is normally received out-of-band. If it is not assigned, the trust anchor
     * entity configuration is downloaded and its self-declared keys are used (which offers no real trust - only
     * intended for test setups).
     */
    @Getter
    @Setter
    private JWKSet jwks;

    /**
     * The resolve endpoint of the trust anchor. Normally not assigned - the endpoint is then read from the
     * {@code federation_entity} metadata of the trust anchor's entity configuration. Assign it if the trust anchor
     * does not publish its entity configuration at its entity identifier, or if it advertises an endpoint that can
     * not be reached from here. The resolve responses are always verified against the trust anchor keys, so the
     * endpoint must be operated by the trust anchor itself.
     */
    @Getter
    @Setter
    private URI resolveEndpoint;

    /**
     * Whether this trust anchor should be traversed when discovering OP:s.
     */
    @Getter
    @Setter
    private boolean discoverOps = true;

    /**
     * The authorities whose subordinate listing endpoints should be invoked when discovering OP:s under this trust
     * anchor. If not assigned, the discovery starts at the trust anchor itself, meaning that the entire federation
     * tree below it is traversed. By pointing out one, or more, intermediates the discovery may be limited to the
     * parts of the federation where OP:s are known to be registered. Note that the resolution of a discovered OP is
     * always made against the trust anchor.
     */
    @Getter
    @NestedConfigurationProperty
    private final List<ListingSourceProperties> subordinateListingSources = new ArrayList<>();

    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.entityId, "testclient.oidc.federation.trust-anchors[].entity-id must be set");
      this.subordinateListingSources.forEach(ListingSourceProperties::afterPropertiesSet);
    }

    /**
     * Gets the authorities to invoke subordinate listings against when discovering OP:s. If no sources have been
     * configured, the trust anchor itself is returned.
     *
     * @return a list of listing sources
     */
    @Nonnull
    public List<ListingSourceProperties> getDiscoverySources() {
      if (this.subordinateListingSources.isEmpty()) {
        final ListingSourceProperties self = new ListingSourceProperties();
        self.setEntityId(this.entityId);
        return List.of(self);
      }
      return List.copyOf(this.subordinateListingSources);
    }
  }

  /**
   * An authority that is invoked when discovering OP:s.
   */
  public static class ListingSourceProperties implements InitializingBean {

    /**
     * The entity identifier of the authority (a trust anchor or an intermediate).
     */
    @Getter
    @Setter
    private String entityId;

    /**
     * The subordinate listing endpoint of the authority. Normally not assigned - the endpoint is then read from the
     * {@code federation_entity} metadata of the authority's entity configuration. Assign it if the authority does
     * not publish its entity configuration at its entity identifier, or if it advertises an endpoint that can not be
     * reached from here.
     */
    @Getter
    @Setter
    private URI listEndpoint;

    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.entityId,
          "testclient.oidc.federation.trust-anchors[].subordinate-listing-sources[].entity-id must be set");
    }
  }

  /**
   * Properties for a trust mark that is published in our entity configurations.
   */
  public static class TrustMarkProperties implements InitializingBean {

    /**
     * The trust mark type, i.e., the identifier of the trust mark. Named {@code id} in the OpenID Federation drafts
     * that preceded 1.0.
     */
    @Getter
    @Setter
    private String trustMarkType;

    /**
     * The entity identifier of the trust mark issuer. The trust mark is fetched from this entity's trust mark
     * endpoint, and must be signed by it. Required, unless the trust mark {@code value} is given.
     */
    @Getter
    @Setter
    private String issuer;

    /**
     * The trust mark endpoint of the issuer. Normally not assigned - the endpoint is then read from the
     * {@code federation_entity} metadata of the issuer's entity configuration. Assign it if the issuer does not
     * publish its entity configuration at its entity identifier, or if it advertises an endpoint that can not be
     * reached from here.
     */
    @Getter
    @Setter
    private URI trustMarkEndpoint;

    /**
     * A pre-issued trust mark (a signed JWT), received out-of-band. If assigned, the trust mark is published as it
     * is - nothing is fetched from the issuer.
     */
    @Getter
    @Setter
    private String value;

    /**
     * Whether the trust mark is required. If a required trust mark can not be obtained, no entity configuration is
     * published for the RP (instead of publishing one without the trust mark).
     */
    @Getter
    @Setter
    private boolean required = false;

    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.trustMarkType, "trust-marks[].trust-mark-type must be set");
      if (!StringUtils.hasText(this.value)) {
        Assert.hasText(this.issuer,
            "trust-marks[].issuer must be set for trust mark %s (unless its value is given)"
                .formatted(this.trustMarkType));
      }
    }
  }

  /**
   * The {@code federation_entity} metadata that is published in our entity configurations.
   */
  public static class FederationEntityMetadataProperties {

    /** The organization name. */
    @Getter
    @Setter
    private String organizationName;

    /** Contacts. */
    @Getter
    @Setter
    private List<String> contacts = new ArrayList<>();

    /** The homepage URI. */
    @Getter
    @Setter
    private String homepageUri;

    /** The policy URI. */
    @Getter
    @Setter
    private String policyUri;

    /** The logo URI. */
    @Getter
    @Setter
    private String logoUri;
  }

}
