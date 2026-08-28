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

import jakarta.annotation.Nonnull;
import net.shibboleth.shared.component.ComponentInitializationException;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingInput;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationException;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.opensaml.sweid.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.time.Duration;
import java.util.List;

/**
 * Custom implementation for validating SAML responses.
 *
 * @author Martin Lindström
 */
public class CustomResponseProcessor extends SwedishEidResponseProcessorImpl {

  public CustomResponseProcessor(@Nonnull final MetadataResolver metadataResolver,
      @Nonnull final List<PkiCredential> decryptCredentials) {

    final List<Credential> credentials = decryptCredentials.stream()
        .map(OpenSamlCredential::new)
        .map(Credential.class::cast)
        .toList();

    this.setDecrypter(new SAMLObjectDecrypter(credentials));
    this.setMetadataResolver(metadataResolver);
    this.setMessageReplayChecker(new InMemoryReplayChecker());
    final ResponseValidationSettings validationSettings = new ResponseValidationSettings();
    validationSettings.setMaxAgeResponse(Duration.ofMinutes(1));
    validationSettings.setStrictValidation(true);
    this.setResponseValidationSettings(validationSettings);

    try {
      this.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new RuntimeException(e);
    }
  }

}
