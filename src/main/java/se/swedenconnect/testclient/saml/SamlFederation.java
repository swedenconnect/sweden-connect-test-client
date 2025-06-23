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
package se.swedenconnect.testclient.saml;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;
import org.w3c.dom.Document;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.testclient.config.SamlProperties;
import se.swedenconnect.testclient.utils.HttpClientUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;

/**
 * A bean that represents a SAML federation.
 *
 * @author Martin Lindström
 */
public class SamlFederation {

  /** The metadata location. */
  private final MetadataLocation metadataLocation;

  /** The textual description of the federation. */
  private final String description;

  /** The metadata provider for this federation. */
  private final MetadataProvider metadataProvider;

  /**
   * Constructor.
   *
   * @param properties the SAML metadata properties
   * @param sslBundles the Spring SSL bundles
   * @throws Exception for errors creating the underlying {@link MetadataProvider}
   */
  public SamlFederation(@Nonnull final SamlProperties.SamlFederationProperties properties,
      @Nonnull final SslBundles sslBundles) throws Exception {

    this.description = properties.getDescription();
    final AbstractMetadataProvider provider;
    if (properties.getMetadataLocation() instanceof final UrlResource urlResource && !urlResource.isFile()) {
      this.metadataLocation = new MetadataLocation(properties.getMetadataLocation().getURL().toString(), true);
      provider = new HTTPMetadataProvider(properties.getMetadataLocation().getURL().toString(),
          preProcessBackupFile(properties.getBackupLocation()),
          HttpClientUtils.createHttpClient(properties.getTls(), sslBundles));
    }
    else if (properties.getMetadataLocation() instanceof FileSystemResource) {
      this.metadataLocation = new MetadataLocation(properties.getMetadataLocation().getFile().getAbsolutePath(), false);
      provider = new FilesystemMetadataProvider(properties.getMetadataLocation().getFile());
    }
    else {
      this.metadataLocation = new MetadataLocation(properties.getMetadataLocation().toString(), false);

      final Document doc = Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool())
          .parse(properties.getMetadataLocation().getInputStream());
      provider = new StaticMetadataProvider(doc.getDocumentElement());
    }

    if (properties.getValidationCertificate() != null) {
      provider.setSignatureVerificationCertificate(properties.getValidationCertificate());
    }
    provider.setPerformSchemaValidation(false);
    provider.initialize();

    this.metadataProvider = provider;
  }

  /**
   * Gets the {@link MetadataProvider} for this federation.
   *
   * @return the {@link MetadataProvider}
   */
  @Nonnull
  public MetadataProvider getMetadataProvider() {
    return this.metadataProvider;
  }

  /**
   * Gets the location from where federation metadata was obtained.
   *
   * @return metadata location
   */
  @Nonnull
  public MetadataLocation getMetadataLocation() {
    return this.metadataLocation;
  }

  /**
   * Gets the textual description for the federation.
   *
   * @return description for the federation
   */
  @Nonnull
  public String getDescription() {
    return this.description;
  }

  /**
   * Gets the last time the metadata was updated.
   *
   * @return the last time the metadata was updated, or {@code null} if it has not been read
   */
  @Nullable
  public Instant getLastUpdate() {
    return this.metadataProvider.getLastUpdate();
  }

  /**
   * Makes sure that all parent directories for the supplied file exists and returns the backup file as an absolute
   * path.
   *
   * @param backupFile the backup file
   * @return the absolute path of the backup file
   */
  @Nullable
  private static String preProcessBackupFile(@Nullable final File backupFile) {
    if (backupFile == null) {
      return null;
    }
    preProcessBackupDirectory(backupFile.getParentFile());
    return backupFile.getAbsolutePath();
  }

  /**
   * Makes sure that all parent directories exists and returns the directory as an absolute path.
   *
   * @param backupDirectory the backup directory
   * @return the absolute path of the backup directory
   */
  @Nullable
  private static String preProcessBackupDirectory(@Nullable final File backupDirectory) {
    if (backupDirectory == null) {
      return null;
    }
    try {
      final Path path = backupDirectory.toPath();
      Files.createDirectories(path);
      return path.toFile().getAbsolutePath();
    }
    catch (final IOException e) {
      throw new IllegalArgumentException("Invalid backup-location");
    }
  }

  /**
   * Stores the metadata location.
   *
   * @param location the location
   * @param isUrl whether the location is a URL
   */
  public record MetadataLocation(String location, @JsonProperty("is_url") boolean isUrl) {
  }

}
