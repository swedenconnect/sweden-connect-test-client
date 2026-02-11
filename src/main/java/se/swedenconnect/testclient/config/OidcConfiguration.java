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

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import jakarta.annotation.Nonnull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.testclient.controllers.OidcController;
import se.swedenconnect.testclient.credentials.ClientCredentials;
import se.swedenconnect.testclient.oidc.OIDCOPMetadataFetcher;
import se.swedenconnect.testclient.oidc.OidcOp;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.utils.UrlBuilderBean;

import java.util.ArrayList;
import java.util.List;

/**
 * OpenID Connect configuration.
 *
 * @author Martin Lindström
 */
@ConditionalOnProperty(prefix = "testclient.oidc", name = "enabled", havingValue = "true", matchIfMissing = false)
@Configuration
public class OidcConfiguration {

  private final OidcProperties properties;
  private final PkiCredentialFactory credentialFactory;
  private final UrlBuilderBean urlBuilder;

  public OidcConfiguration(@Nonnull final OidcProperties properties,
      @Nonnull final PkiCredentialFactory credentialFactory, @Nonnull final UrlBuilderBean urlBuilder) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
    this.urlBuilder = urlBuilder;
  }

  @Bean("testclient.oidc.fed.authorities")
  List<EntityID> oidcFedAuthorities() {
    return this.properties.getOpenidFedAuthorities().stream()
        .map(EntityID::new)
        .toList();
  }

  @Bean
  OIDCOPMetadataFetcher metadataFetcher() {
    return new OIDCOPMetadataFetcher(RestClient.builder().build());
  }

  @Bean("testclient.oidc.OpList")
  List<OidcOp> oidcOps() {
    return this.properties.getOps().stream().map(p -> OidcOp.builder()
        .entityId(p.getEntityId())
        .displayName(p.getDisplayName())
        .description(p.getDescription())
        .authorizationEndpoint(p.getAuthorizationEndpoint())
        .metadataEndpoint(p.getMetadataEndpoint())
        .tokenEndpoint(p.getTokenEndpoint())
        .userInfoEndpoint(p.getUserInfoEndpoint())
        .logoutEndpoint(p.getLogoutEndpoint())
        .build()
    ).toList();
  }

  @Bean("testclient.oidc.RpList")
  List<OidcRp> oidcRps(
      @Qualifier("testclient.BaseUrl") @Nonnull final String baseUrl,
      @Qualifier("testclient.DefaultCredential") @Nonnull final PkiCredential defaultCredential,
      @Qualifier("testclient.NonRegisteredCredential") @Nonnull final PkiCredential nonRegisteredCredential)
      throws Exception {

    final List<String> entityIds = new ArrayList<>();
    final List<OidcRp> rps = new ArrayList<>();
    for (final OidcRpProperties p : this.properties.getRps()) {
      final String entityId = this.urlBuilder.buildUrl(p.getPathSuffix());
      if (entityIds.contains(entityId)) {
        throw new IllegalArgumentException("Several OIDC RP:s with the same entityId: " + entityId);
      }
      entityIds.add(entityId);

      rps.add(new OidcRp(entityId, p.getDescription(), p.getPathSuffix(),
          ClientCredentials.create(
              this.credentialFactory, p.getCredentials(), defaultCredential, nonRegisteredCredential),
          p.getMetadata(), this.urlBuilder.buildUrl(OidcController.REDIRECTION_URL_BASE, p.getPathSuffix())));
    }
    return rps;
  }

}
