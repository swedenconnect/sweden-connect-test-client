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
package se.swedenconnect.testclient.controllers;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.testclient.saml.SamlSp;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Controller for displaying SAML SP metadata.
 *
 * @author Martin Lindström
 */
@Controller
@Slf4j
public class SamlSpMetadataController {

  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";

  /** Base path for where SP metadata are published. */
  public static final String SP_METADATA_BASEPATH = "/saml/metadata";

  /** The entity descriptors for this controller. */
  private final Map<String, EntityDescriptorContainer> entityDescriptors;

  /**
   * Constructor.
   *
   * @param sps the SAML SP:s
   */
  public SamlSpMetadataController(@Nonnull final List<SamlSp> sps) {
    Objects.requireNonNull(sps, "sps must not be null");
    this.entityDescriptors = sps.stream()
        .collect(Collectors.toMap(SamlSp::getPathPrefix, SamlSp::getEntityDescriptorContainer));
  }

  /**
   * Supplies the SAML metadata document for the given SP.
   *
   * @param request the HTTP servlet request
   * @param sp the path prefix for the SP
   * @param acceptHeader the Accept header
   * @return an XML document
   */
  @GetMapping(value = SP_METADATA_BASEPATH + "/{sp}",
      produces = { APPLICATION_SAML_METADATA, MediaType.APPLICATION_XML_VALUE })
  @ResponseBody
  public HttpEntity<byte[]> getMetadata(@Nonnull final HttpServletRequest request,
      @PathVariable(value = "sp") @Nonnull final String sp,
      @RequestHeader(name = "Accept", required = false) @Nonnull final String acceptHeader) {

    final EntityDescriptorContainer container = Optional.ofNullable(this.entityDescriptors.get(sp))
        .orElseThrow(() -> new NotFoundException("No metadata published at %s%s".formatted(SP_METADATA_BASEPATH, sp)));

    log.debug("Request to download metadata from {} by client at {}", request.getRequestURI(), request.getRemoteAddr());

    try {
      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (container.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        container.update(true);
        log.debug("Metadata was updated and signed");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      // Get the DOM for the metadata and serialize it.
      //
      final Element dom = container.marshall();

      final ByteArrayOutputStream stream = new ByteArrayOutputStream();
      SerializeSupport.writeNode(dom, stream);

      // Assign the HTTP headers.
      //
      final HttpHeaders header = new HttpHeaders();
      if (acceptHeader != null && !acceptHeader.contains(APPLICATION_SAML_METADATA)) {
        header.setContentType(MediaType.APPLICATION_XML);
      }
      else {
        header.setContentType(MediaType.valueOf(APPLICATION_SAML_METADATA));
      }

      final byte[] documentBody = stream.toByteArray();
      header.setContentLength(documentBody.length);
      return new HttpEntity<>(documentBody, header);
    }
    catch (final SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

}
