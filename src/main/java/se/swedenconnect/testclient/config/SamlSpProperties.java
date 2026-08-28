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
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.testclient.credentials.ClientCredentialsProperties;

import java.util.List;

/**
 * Configuration properties for a SAML SP.
 *
 * @author Martin Lindström
 */
public class SamlSpProperties implements InitializingBean {

  /**
   * The SAML entityID for the SP.
   */
  @Getter
  @Setter
  private String entityId;

  /**
   * Description of the SP.
   */
  @Getter
  @Setter
  private String description;

  /**
   * The path suffix to use in SAML URL:s for this SP.
   */
  @Getter
  @Setter
  private String pathSuffix;

  /**
   * The SAML SP credentials.
   */
  @Getter
  @Setter
  private ClientCredentialsProperties credentials;

  /**
   * SAML SP metadata settings.
   */
  @Getter
  @NestedConfigurationProperty
  private final SpMetadataProperties metadata = new SpMetadataProperties();

  @Override
  public void afterPropertiesSet() {
    Assert.hasText(this.entityId, "Missing entity-id for SAML SP");
    Assert.hasText(this.description, "Missing description for SAML SP");
    Assert.hasText(this.pathSuffix, "Missing path-suffix for SAML SP");
    this.metadata.afterPropertiesSet();
  }

  /**
   * SAML SP metadata properties.
   */
  public static class SpMetadataProperties implements InitializingBean {

    /**
     * The entitity categories for the SP. If provided, it overrides the default entity catgeories.
     */
    @Getter
    @Setter
    private List<String> entityCategories;

    /**
     * Whether the SP wants assertions to be signed.
     */
    @Getter
    @Setter
    private Boolean wantsAssertionsSigned;

    /**
     * The NameID formats that are supported.
     */
    @Getter
    @Setter
    private List<String> nameIdFormats;

    /**
     * SP UI Info.
     */
    @Getter
    @Setter
    private UiInfoProperties uiInfo;

    /**
     * Attribute consuming services.
     */
    @Getter
    @Setter
    private List<AttributeConsumingServiceProperties> attributeConsumingServices;

    @Override
    public void afterPropertiesSet() {
      if (this.entityCategories != null && this.entityCategories.isEmpty()) {
        this.entityCategories = null;
      }
      if (this.nameIdFormats != null && this.nameIdFormats.isEmpty()) {
        this.nameIdFormats = null;
      }
      if (this.attributeConsumingServices != null) {
        this.attributeConsumingServices.forEach(AttributeConsumingServiceProperties::afterPropertiesSet);
        final long noDefaults = this.attributeConsumingServices.stream()
            .filter(a -> a.getIsDefault() != null && a.getIsDefault())
            .count();
        if (noDefaults > 1) {
          throw new IllegalArgumentException("More than one attribute consuming service is marked as default");
        }
        if (noDefaults == 0 && !this.attributeConsumingServices.isEmpty()) {
          this.attributeConsumingServices.getFirst().setIsDefault(true);
        }
      }
    }

    /**
     * Properties for the {@code mdui:UIInfo} metadata element.
     */
    public static class UiInfoProperties {

      /**
       * Display names for the SP.
       */
      @Getter
      @Setter
      private List<LocalizedString> displayName;

      /**
       * Description for the SP.
       */
      @Getter
      @Setter
      private List<LocalizedString> description;

    }

    /**
     * Configuration properties for an {@code AttributeConsumingService}.
     */
    public static class AttributeConsumingServiceProperties implements InitializingBean {

      /**
       * The service name.
       */
      @Getter
      @Setter
      private List<LocalizedString> serviceName;

      /**
       * Whether this is the default entry.
       */
      @Getter
      @Setter
      private Boolean isDefault;

      /**
       * The requested attributes.
       */
      @Getter
      @Setter
      private List<RequestedAttributeProperties> requestedAttributes;

      @Override
      public void afterPropertiesSet() {
        Assert.notEmpty(this.serviceName, "Missing service name for SAML SP");
        if (this.requestedAttributes != null) {
          this.requestedAttributes.forEach(RequestedAttributeProperties::afterPropertiesSet);
        }
      }

      /**
       * Represents a requested attribute.
       */
      public static class RequestedAttributeProperties implements InitializingBean {

        /**
         * The attribute name.
         */
        @Getter
        @Setter
        private String attributeName;

        /**
         * Whether the attribute is required or not.
         */
        @Getter
        @Setter
        private Boolean required;

        @Override
        public void afterPropertiesSet() {
          Assert.hasText(this.attributeName, "Missing required attribute name");
        }
      }
    }

  }

}
