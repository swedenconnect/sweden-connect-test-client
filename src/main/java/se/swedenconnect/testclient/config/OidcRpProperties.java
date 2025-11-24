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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import se.swedenconnect.testclient.credentials.ClientCredentialsProperties;

/**
 * Configuration properties for an OIDC RP.
 *
 * @author Martin Lindström
 */
public class OidcRpProperties implements InitializingBean {

  /**
   * The path suffix to use in OIDC URL:s for this RP. The suffix is appended to the base URL of the application.
   */
  @Getter
  @Setter
  private String pathSuffix;

  /**
   * Description of the RP.
   */
  @Getter
  @Setter
  private String description;

  /**
   * The OIDC RP credentials.
   */
  @Getter
  @Setter
  private ClientCredentialsProperties credentials;

  /**
   * The RP metadata. Expressed as JSON.
   */
  @Getter
  @Setter
  private String metadata;

  @Override
  public void afterPropertiesSet() {
    Assert.hasText(this.pathSuffix, "Missing path-suffix for OIDC OP");
    Assert.hasText(this.description, "Missing description for OIDC OP");
    Assert.hasText(this.metadata, "Missing metadata for OIDC OP");
  }

}
