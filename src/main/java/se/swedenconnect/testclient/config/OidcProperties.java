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
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for OIDC support.
 *
 * @author Martin Lindström
 */
public class OidcProperties implements InitializingBean {

  /**
   * Whether OIDC is enabled.
   */
  @Getter
  @Setter
  private boolean enabled = false;

  /**
   * A list of immediate superiors of the RP:s (for OpenID federation).
   */
  @Getter
  @Setter
  private List<String> openidFedAuthorities;

  /**
   * The Relying Parties.
   */
  @Getter
  @NestedConfigurationProperty
  private final List<OidcRpProperties> rps = new ArrayList<>();

  /**
   * The OpenId Providers to test.
   */
  @Getter
  @NestedConfigurationProperty
  private final List<OidcOpProperties> ops = new ArrayList<>();

  @Override
  public void afterPropertiesSet() {
    if (this.enabled) {
      Assert.notEmpty(this.openidFedAuthorities, "testclient.oidc.openid-fed-authorities must be set");
      Assert.notEmpty(this.rps, "testclient.oidc.rps is required (at least one RP must be configured)");
      this.rps.forEach(OidcRpProperties::afterPropertiesSet);
    }
  }

  public static class OidcFederationProperties implements InitializingBean {

    @Getter
    @Setter
    private String authority;

    @Getter
    @Setter
    private String trustAnchor;

    @Getter
    @Setter
    private JWKSet trustJwks;

    @Override
    public void afterPropertiesSet() {
    }

  }

}
