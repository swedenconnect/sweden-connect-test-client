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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

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
   * Sorting order of the OP:s in the OP selection list. A pattern matches an OP if it occurs anywhere in its entity
   * identifier, ignoring case. OP:s are grouped by the first pattern they match, in the order the patterns are given,
   * and OP:s matching no pattern come last.
   */
  @Getter
  private final List<String> opSorting = new ArrayList<>();

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

  /**
   * OpenID Federation settings.
   */
  @Getter
  @NestedConfigurationProperty
  private final OidfProperties federation = new OidfProperties();

  @Override
  public void afterPropertiesSet() {
    if (this.enabled) {
      Assert.notEmpty(this.rps, "testclient.oidc.rps is required (at least one RP must be configured)");
      this.rps.forEach(OidcRpProperties::afterPropertiesSet);
      this.federation.afterPropertiesSet();
      if (this.federation.isEnabled()) {
        Assert.notEmpty(this.openidFedAuthorities,
            "testclient.oidc.openid-fed-authorities must be set when OpenID Federation is enabled");
      }
      for (int i = 0; i < this.ops.size(); i++) {
        this.validateOp(this.ops.get(i), i);
      }
    }
    if (this.openidFedAuthorities == null) {
      this.openidFedAuthorities = new ArrayList<>();
    }
  }

  private void validateOp(final OidcOpProperties op, final int index) {
    final String opId = StringUtils.hasText(op.getEntityId()) ? op.getEntityId() : "ops[%d]".formatted(index);
    Assert.hasText(op.getAuthorizationEndpoint(),
        "Missing authorization-endpoint for OIDC OP '%s'".formatted(opId));
    Assert.hasText(op.getTokenEndpoint(),
        "Missing token-endpoint for OIDC OP '%s'".formatted(opId));
    Assert.hasText(op.getUserInfoEndpoint(),
        "Missing user-info-endpoint for OIDC OP '%s'".formatted(opId));
    Assert.hasText(op.getMetadataEndpoint(),
        "Missing metadata-endpoint for OIDC OP '%s'".formatted(opId));
  }

}
