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
package se.swedenconnect.testclient.saml;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import net.shibboleth.shared.resolver.ResolverException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;
import org.w3c.dom.Document;
import se.swedenconnect.opensaml.saml2.metadata.provider.AbstractMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.CompositeMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.metadata.provider.StaticMetadataProvider;
import se.swedenconnect.testclient.config.ClientTlsProperties;
import se.swedenconnect.testclient.config.SamlProperties;
import se.swedenconnect.testclient.utils.HttpClientUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A bean that represents a SAML federation.
 *
 * @author Martin Lindström
 */
public class SamlFederation {

  /** IdP Cache lifetime. */
  public static final Duration IDP_CACHE_LIFETIME = Duration.ofMinutes(10);

  /** The textual description of the federation. */
  private final String description;

  /** The metadata provider for this federation. */
  private final MetadataProvider metadataProvider;

  /** IdP sorting order. */
  private final List<String> idpSortingOrder;

  /** Cache of IdP:s. */
  private List<EntityDescriptor> idpCache;

  /** When the cache was updated last. */
  private Instant cacheLastUpdate;

  /**
   * Constructor.
   *
   * @param properties the SAML metadata properties
   * @param sslBundles the Spring SSL bundles
   * @param clientTls client TLS properties
   * @throws Exception for errors creating the underlying {@link MetadataProvider}
   */
  public SamlFederation(@Nonnull final SamlProperties.SamlFederationProperties properties,
      @Nonnull final SslBundles sslBundles, @Nonnull final ClientTlsProperties clientTls) throws Exception {

    this.description = properties.getDescription();
    this.metadataProvider = createMetadataProvider(properties.getSource(), sslBundles, clientTls);
    this.idpSortingOrder = properties.getIdpSorting();
  }

  @Nonnull
  private static MetadataProvider createMetadataProvider(
      @Nonnull final List<SamlProperties.SamlFederationProperties.FederationSource> sources,
      @Nullable final SslBundles sslBundles, @Nonnull final ClientTlsProperties clientTls) throws Exception {

    final List<MetadataProvider> providers = new ArrayList<>();
    for (final SamlProperties.SamlFederationProperties.FederationSource md : sources) {
      final AbstractMetadataProvider provider;
      if (md.getMetadataLocation() instanceof final UrlResource urlResource && !urlResource.isFile()) {
        provider = new HTTPMetadataProvider(md.getMetadataLocation().getURL().toString(),
            preProcessBackupFile(md.getBackupLocation()), HttpClientUtils.createHttpClient(clientTls, sslBundles));
        if (md.getValidationCertificate() != null) {
          provider.setSignatureVerificationCertificate(md.getValidationCertificate());
        }
      }
      else if (md.getMetadataLocation() instanceof FileSystemResource) {
        provider = new FilesystemMetadataProvider(md.getMetadataLocation().getFile());
      }
      else {
        final Document doc = Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool())
            .parse(md.getMetadataLocation().getInputStream());
        provider = new StaticMetadataProvider(doc.getDocumentElement());
      }
      provider.setPerformSchemaValidation(false);
      provider.initialize();
      providers.add(provider);
    }
    if (providers.size() > 1) {
      final CompositeMetadataProvider compositeProvider =
          new CompositeMetadataProvider("composite-provider", providers);
      compositeProvider.initialize();
      return compositeProvider;
    }
    else {
      return providers.getFirst();
    }
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
   * Gets a list of all IdP:s available (according to the defined sorting order).
   *
   * @return a list of all IdP:s available
   * @throws ResolverException if fetching IdP:s fail
   */
  @Nonnull
  public synchronized List<EntityDescriptor> getIdps() throws ResolverException {
    if (this.idpCache == null || this.cacheLastUpdate == null
        || this.cacheLastUpdate.plus(IDP_CACHE_LIFETIME).isBefore(Instant.now())) {
      final List<List<EntityDescriptor>> sortedIdps = new ArrayList<>();
      this.idpSortingOrder.forEach(x -> sortedIdps.add(new ArrayList<>()));
      sortedIdps.add(new ArrayList<>());
      final List<EntityDescriptor> idps = this.metadataProvider.getIdentityProviders();
      for (final EntityDescriptor idp : idps) {
        boolean sortMatch = false;
        for (int i = 0; i < this.idpSortingOrder.size(); i++) {
          if (idps.get(i).getEntityID().toLowerCase().contains(this.idpSortingOrder.get(i).toLowerCase())) {
            sortedIdps.get(i).add(idp);
            sortMatch = true;
            break;
          }
        }
        if (!sortMatch) {
          sortedIdps.getLast().add(idp);
        }
      }
      this.idpCache = sortedIdps.stream().flatMap(List::stream).collect(Collectors.toList());
      this.cacheLastUpdate = Instant.now();
    }
    return this.idpCache;
  }

  /**
   * Gets the metadata for the given entityID.
   *
   * @param idp the IdP entityID
   * @return an {@link EntityDescriptor} or {@code null}
   * @throws ResolverException for resolver errors
   */
  @Nullable
  public synchronized EntityDescriptor getIdp(@Nonnull final String idp) throws ResolverException {
    return this.metadataProvider.getEntityDescriptor(idp);
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

}
