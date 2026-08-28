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

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.x509.X509Credential;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGenerator;

/**
 * Generator for creating {@link org.opensaml.saml.saml2.core.AuthnRequest AuthnRequest} objects.
 *
 * @author Martin Lindström
 */
public class TestAuthnRequestGenerator extends SwedishEidAuthnRequestGenerator {

  public TestAuthnRequestGenerator(final EntityDescriptor spMetadata,
      final X509Credential signCredential, final MetadataResolver metadataResolver) {
    super(spMetadata, signCredential, metadataResolver);
  }

}
