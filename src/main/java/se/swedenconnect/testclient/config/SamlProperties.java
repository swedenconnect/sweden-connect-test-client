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
package se.swedenconnect.testclient.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.util.Assert;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for SAML.
 *
 * @author Martin Lindström
 */
@Slf4j
public class SamlProperties implements InitializingBean {

  /**
   * Whether SAML is enabled.
   */
  @Getter
  @Setter
  private boolean enabled = false;

  /**
   * SAML federation settings.
   */
  @Getter
  @NestedConfigurationProperty
  private final SamlFederationProperties federation = new SamlFederationProperties();

  /**
   * Common metadata settings for all SP:s.
   */
  @Getter
  @NestedConfigurationProperty
  private final CommonSpMetadataProperties commonMetadata = new CommonSpMetadataProperties();

  /**
   * The SP:s.
   */
  @Getter
  @NestedConfigurationProperty
  private final List<SamlSpProperties> sps = new ArrayList<>();

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() {
    if (this.enabled) {
      Assert.notNull(this.federation, "testclient.saml.federation.* is required");
      this.federation.afterPropertiesSet();
      this.commonMetadata.afterPropertiesSet();
      Assert.notEmpty(this.sps, "testclient.saml.sps is required (at least one SP must be configured)");
      this.sps.forEach(SamlSpProperties::afterPropertiesSet);
    }
  }

  /**
   * Configuration settings for the SAML federation.
   */
  public static class SamlFederationProperties implements InitializingBean {

    /**
     * Textual description of the federation(s).
     */
    @Getter
    @Setter
    private String description;

    /**
     * The federation source(s).
     */
    @Getter
    private final List<FederationSource> source = new ArrayList<>();

    /**
     * Sorting order in UI of IdP:s.
     */
    @Getter
    private final List<String> idpSorting = new ArrayList<>();

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      Assert.hasText(this.description, "testclient.saml.federation.description is required");
      if (this.source.isEmpty()) {
        throw new IllegalArgumentException(
            "testclient.saml.federation.source.* is empty. At least one federation source must be configured");
      }
      for (final FederationSource s : this.source) {
        s.afterPropertiesSet();
      }
    }

    /**
     * Configuration properties for a federation source.
     */
    public static class FederationSource implements InitializingBean {

      /**
       * The location for where to download the federation metadata. Can be a URL or a static file.
       */
      @Getter
      @Setter
      private Resource metadataLocation;

      /**
       * The certificate to be used for validating the signature of the downloaded metadata. If not given, no validation
       * of the metadata will be performed.
       */
      @Getter
      @Setter
      private X509Certificate validationCertificate;

      /**
       * The location to the file where downloaded metadata should be cached.
       */
      @Getter
      @Setter
      private File backupLocation;

      /** {@inheritDoc} */
      @Override
      public void afterPropertiesSet() {
        Assert.notNull(this.metadataLocation, "testclient.saml.federation.source[].metadata-location is required");
        if (this.validationCertificate == null) {
          log.warn("testclient.saml.federation.source[].validation-certificate is not set - "
              + "No validation of downloaded metadata will be performed");
        }
        if (this.backupLocation == null) {
          if (this.metadataLocation instanceof final UrlResource urlResource && !urlResource.isFile()) {
            log.warn("testclient.saml.federation.source[].backup-location is not set - "
                + "It is strongly recommended to use a cache for downloaded metadata");
          }
        }
      }

    }

  }

  /**
   * Metadata properties shared by all SP instances.
   */
  public static class CommonSpMetadataProperties implements InitializingBean {

    /**
     * Optional template file for SAML SP metadata.
     */
    @Getter
    @Setter
    private Resource metadataTemplate;

    @Getter
    private final List<String> defaultEntityCategories = new ArrayList<>();

    @Override
    public void afterPropertiesSet() {
    }

  }

}
