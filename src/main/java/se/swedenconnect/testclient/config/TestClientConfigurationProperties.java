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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.Assert;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;

/**
 * Configuration properties for the Sweden Connect Test Client application.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("testclient")
public class TestClientConfigurationProperties implements InitializingBean {

  /**
   * The base URL for the application. This includes the protocol, domain, and possibly the port and context path.
   */
  @Getter
  @Setter
  private String baseUrl;

  /**
   * The default credential to use if no signing or encryption credential is given for a client.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties defaultCredential;

  /**
   * A credential that no client will register. Will be used for testing error handling at IdP/OP.
   */
  @Getter
  @Setter
  private PkiCredentialConfigurationProperties nonRegisteredCredential;

  /**
   * Client TLS settings.
   */
  @Getter
  @Setter
  private ClientTlsProperties tls;

  /** The SAML settings. */
  @Getter
  @NestedConfigurationProperty
  private SamlProperties saml = new SamlProperties();

  /** The OIDC settings. */
  @Getter
  @NestedConfigurationProperty
  private OidcProperties oidc = new OidcProperties();

  @Override
  public void afterPropertiesSet() {
    Assert.hasText(this.baseUrl, "testclient.base-url must be set");
    Assert.notNull(this.nonRegisteredCredential, "testclient.non-registered-credential must not be null");
    this.saml.afterPropertiesSet();
    this.oidc.afterPropertiesSet();
  }
}
