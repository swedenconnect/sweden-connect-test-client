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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.testclient.saml.SamlFederation;
import se.swedenconnect.testclient.saml.SamlSp;
import se.swedenconnect.testclient.utils.ClientCredentials;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the Sweden Connect Test Client configuration.
 *
 * @author Martin Lindström
 */
@Configuration
@DependsOn("openSAML")
@EnableConfigurationProperties(TestClientConfigurationProperties.class)
public class TestClientConfiguration {

  private final TestClientConfigurationProperties properties;

  private final PkiCredentialFactory credentialFactory;

  private final SslBundles sslBundles;

  public TestClientConfiguration(@Nonnull final TestClientConfigurationProperties properties,
      @Nonnull final PkiCredentialFactory credentialFactory, @Nonnull final SslBundles sslBundles) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
    this.sslBundles = sslBundles;
  }

  @Bean
  @Nonnull
  SamlFederation samlFederation() throws Exception {
    return new SamlFederation(this.properties.getSaml().getFederation(), this.sslBundles);
  }

  @Bean("testclient.DefaultCredential")
  @Nullable
  PkiCredential defaultCredential() throws Exception {
    return this.properties.getDefaultCredential() != null
        ? this.credentialFactory.createCredential(this.properties.getDefaultCredential())
        : null;
  }

  @Bean
  List<SamlSp> getSamlSps() throws Exception {
    final List<SamlSp> sps = new ArrayList<>();
    for (final SamlSpProperties spp : this.properties.getSaml().getSps()) {
      sps.add(new SamlSp(spp.getEntityId(), this.createClientCredentials(spp.getCredentials())));
    }
    return sps;
  }

  private ClientCredentials createClientCredentials(@Nullable final SamlSpProperties.CredentialsProperties cp)
      throws Exception {
    if (cp == null) {
      return new ClientCredentials(null, null, null, null, null, this.defaultCredential());
    }
    return new ClientCredentials(
        cp.getSigning() != null ? this.credentialFactory.createCredential(cp.getSigning()) : null,
        cp.getFutureSigningCertificate(),
        cp.getEncryption() != null ? this.credentialFactory.createCredential(cp.getEncryption()) : null,
        cp.getPreviousEncryption() != null ? this.credentialFactory.createCredential(cp.getPreviousEncryption()) : null,
        cp.getMetadata() != null ? this.credentialFactory.createCredential(cp.getMetadata()) : null,
        this.defaultCredential());
  }

}
