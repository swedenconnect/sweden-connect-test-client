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

/**
 * Configuration properties for SAML.
 *
 * @author Martin Lindström
 */
@Slf4j
public class SamlConfigurationProperties implements InitializingBean {

  /**
   * SAML federation settings.
   */
  @Getter
  @NestedConfigurationProperty
  private final SamlFederationProperties federation = new SamlFederationProperties();

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.federation, "testclient.saml.federation.* is required");
    this.federation.afterPropertiesSet();
  }

  /**
   * Configuration settings for the SAML federation.
   */
  public static class SamlFederationProperties implements InitializingBean {

    /**
     * Textual description of the federation.
     */
    @Getter
    @Setter
    private String description;

    /**
     * The location for where to download the federation metadata.
     */
    @Getter
    @Setter
    private Resource metadataLocation;

    /**
     * When the {@code metadataLocation} is an HTTPS resource, it is possible to configure the client TLS settings.
     */
    @Getter
    @Setter
    private ClientTlsProperties tls;

    /**
     * The certificate to be used for validating the signature of the downloaded metadata.
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
      Assert.hasText(this.description, "testclient.saml.federation.description is required");
      Assert.notNull(this.metadataLocation, "testclient.saml.federation.metadata-location is required");
      if (this.validationCertificate == null) {
        log.warn("testclient.saml.federation.validation-certificate is not set - "
            + "No validation of downloaded metadata will be performed");
      }
      if (this.backupLocation == null) {
        if (this.metadataLocation instanceof final UrlResource urlResource && !urlResource.isFile()) {
          log.warn("testclient.saml.federation.backup-location is not set - "
              + "It is strongly recommended to use a cache for downloaded metadata");
        }
      }
    }
  }

}
