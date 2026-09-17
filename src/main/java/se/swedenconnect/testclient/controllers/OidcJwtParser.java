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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.testclient.oidc.OidcRp;
import se.swedenconnect.testclient.utils.JoseUtils;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads the JWT:s and JSON objects that an OP delivers - the ID token and the UserInfo response - decrypting them with
 * the keys of the RP, and reports how they were protected.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@Slf4j
public final class OidcJwtParser {

  /** Mapper used for JSON UserInfo responses. */
  private static final ObjectMapper objectMapper = JsonMapper.builder().build();

  /**
   * The claims of a JWT together with a description of how it was protected.
   *
   * @param claims the claims of the JWT (empty if it could not be parsed or decrypted)
   * @param protection how the JWT was protected
   */
  public record ProtectedJwt(@Nonnull Map<String, Object> claims, @Nonnull ProtectionInfo protection) {
  }

  /**
   * Parses a UserInfo response, which is either a plain JSON object or a JWT (signed and/or encrypted).
   *
   * @param contentType the content type of the response (may be {@code null})
   * @param body the response body (may be {@code null})
   * @param rp the relying party (holding the keys needed for decryption)
   * @return the UserInfo claims along with how they were protected
   */
  @Nonnull
  public static ProtectedJwt parseUserInfo(@Nullable final MediaType contentType, @Nullable final String body,
      @Nonnull final OidcRp rp) {
    final String contents = Optional.ofNullable(body).orElse("");
    if (Objects.nonNull(contentType) && contentType.getSubtype().toLowerCase().contains("jwt")) {
      return parseProtectedJwt(contents, rp);
    }
    try {
      final Map<String, Object> claims =
          objectMapper.readerFor(Map.class).readValue(contents);
      return new ProtectedJwt(new HashMap<>(claims), ProtectionInfo.builder().format("JSON").build());
    }
    catch (final Exception e) {
      log.warn("Failed to parse UserInfo response", e);
      return new ProtectedJwt(new HashMap<>(), ProtectionInfo.builder()
          .note("Failed to parse UserInfo response: %s".formatted(e.getMessage()))
          .build());
    }
  }

  /**
   * Parses a JWT that may be signed, encrypted, encrypted and signed, or neither, and reports how it was protected.
   *
   * @param token the serialized JWT
   * @param rp the relying party (holding the keys needed for decryption)
   * @return the claims of the JWT along with how it was protected
   */
  @Nonnull
  public static ProtectedJwt parseProtectedJwt(@Nullable final String token, @Nonnull final OidcRp rp) {
    final ProtectionInfo.ProtectionInfoBuilder protection = ProtectionInfo.builder();
    if (Objects.isNull(token) || token.isBlank()) {
      return new ProtectedJwt(new HashMap<>(), ProtectionInfo.builder().note("Not present in the response").build());
    }
    try {
      JWT jwt = JWTParser.parse(token);
      if (jwt instanceof final EncryptedJWT encrypted) {
        final JWEHeader header = encrypted.getHeader();
        protection.encrypted(true)
            .format("Encrypted JWT")
            .encryptionAlgorithm(Optional.ofNullable(header.getAlgorithm()).map(Object::toString).orElse(null))
            .encryptionMethod(
                Optional.ofNullable(header.getEncryptionMethod()).map(EncryptionMethod::getName).orElse(null))
            .encryptionKeyId(header.getKeyID());

        final Optional<JWT> decrypted = decrypt(encrypted, rp);
        if (decrypted.isEmpty()) {
          return new ProtectedJwt(new HashMap<>(), protection
              .note("Could not be decrypted with any of the client's encryption keys")
              .build());
        }
        jwt = decrypted.get();
      }
      if (jwt instanceof final SignedJWT signed) {
        final JWSHeader header = signed.getHeader();
        protection.signed(true)
            .signatureAlgorithm(Optional.ofNullable(header.getAlgorithm()).map(Object::toString).orElse(null))
            .signatureKeyId(header.getKeyID())
            .signatureType(Optional.ofNullable(header.getType()).map(JOSEObjectType::toString).orElse(null));
      }
      final ProtectionInfo built = protection.build();
      if (Objects.isNull(built.getFormat())) {
        built.setFormat(built.isSigned() ? "Signed JWT" : "Plain JWT");
      }
      return new ProtectedJwt(new HashMap<>(jwt.getJWTClaimsSet().toJSONObject()), built);
    }
    catch (final ParseException e) {
      log.warn("Failed to parse JWT", e);
      return new ProtectedJwt(new HashMap<>(),
          protection.note("Failed to parse: %s".formatted(e.getMessage())).build());
    }
  }

  /**
   * Attempts to decrypt an encrypted JWT using the encryption credentials of the relying party.
   *
   * @param encrypted the encrypted JWT
   * @param rp the relying party
   * @return the decrypted JWT - a {@link SignedJWT} if the payload is a nested signed JWT - or an empty
   *     {@link Optional} if decryption failed
   */
  @Nonnull
  private static Optional<JWT> decrypt(@Nonnull final EncryptedJWT encrypted, @Nonnull final OidcRp rp) {
    for (final PkiCredential credential : rp.getCredentials().getCredentialsForEncryption()) {
      try {
        encrypted.decrypt(JoseUtils.decrypter(credential));
        return Optional.of(Optional.ofNullable(encrypted.getPayload().toSignedJWT())
            .map(JWT.class::cast)
            .orElse(encrypted));
      }
      catch (final Exception e) {
        log.debug("Failed to decrypt JWT using credential '{}'", credential.getName(), e);
      }
    }
    return Optional.empty();
  }

  private OidcJwtParser() {
  }
}
