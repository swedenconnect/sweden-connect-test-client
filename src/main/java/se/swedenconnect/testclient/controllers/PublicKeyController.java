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
package se.swedenconnect.testclient.controllers;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.nimbus.JwkTransformerFunction;

import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;

@AllArgsConstructor
@RestController
public class PublicKeyController {

  private final CredentialBundles bundles;

  @GetMapping("/key/{name}/{format}")
  public String getKey(
      @PathVariable("name") final String name,
      @PathVariable("format") final String format
  ) throws CertificateEncodingException {
    final PkiCredential credential = bundles.getCredential(name);
    if ("JWK".equals(format)) {
      return new JwkTransformerFunction()
          .serializable()
          .apply(credential)
          .toPublicJWK()
          .toJSONString();
    }
    if ("PEM".equals(format)) {
      final String base64 = new String(Base64.getEncoder().encode(credential.getCertificate().getEncoded()), Charset.defaultCharset());
      StringBuilder pem = new StringBuilder();
      pem.append("-----BEGIN CERTIFICATE-----");
      pem.append("\n");

      int index = 0;
      while (index < base64.length()) {
        pem.append(base64, index, Math.min(index + 64, base64.length()));
        pem.append("\n");
        index += 64;
      }

      pem.append("-----END CERTIFICATE-----");
      return pem.toString();
    }
    throw new IllegalArgumentException("Could not determine format %s".formatted(format));
  }
}
