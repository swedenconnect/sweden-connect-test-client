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

import jakarta.annotation.Nonnull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import se.swedenconnect.testclient.oidc.OidcRp;

import java.util.List;

/**
 * Generates a simple, per-RP logotype - the Sweden Connect mosaic with the RP's path suffix written next to it.
 * <p>
 * An RP's logotype is published at {@code <base-url>/<path-suffix>/logo.svg}. This is the URL substituted in for the
 * {@link #LOGO_PLACEHOLDER} token in an RP's configured metadata (see {@link OidcRp}).
 * </p>
 *
 * @author Per Fredrik Plars
 */
@RestController
@ConditionalOnProperty(value = "testclient.oidc.enabled", havingValue = "true")
public class OidcRpLogoController {

  /** The placeholder token that, when used as a metadata value, is replaced by the generated logotype's URL. */
  public static final String LOGO_PLACEHOLDER = "<logo>";

  /** The mosaic - a scaled down copy of {@code /images/logo-notext.svg} - placed to the left of the RP name. */
  private static final String MOSAIC = """
      <g transform="scale(0.25)">
      <rect x="64" width="64" height="64" fill="#CD7A6E"/>
      <rect x="128" y="64" width="64" height="64" fill="#695F59"/>
      <rect x="192" y="64" width="64" height="64" fill="#B4AFAC"/>
      <path d="M0 128H64V192H0V128Z" fill="#5A6751"/>
      <rect x="64" y="128" width="64" height="64" fill="#ACB3A8"/>
      <rect x="192" y="128" width="64" height="64" fill="#F4E0CE"/>
      <rect x="128" y="192" width="64" height="64" fill="#D59151"/>
      </g>""";

  /** The horizontal position where the RP name starts, i.e., the width reserved for the mosaic. */
  private static final double TEXT_X = 84;

  /** The font size used for the RP name. */
  private static final double FONT_SIZE = 28;

  /** The OIDC RP:s. */
  private final List<OidcRp> rps;

  /**
   * Constructor.
   *
   * @param rps the OIDC RP:s
   */
  public OidcRpLogoController(@Qualifier("testclient.oidc.RpList") @Nonnull final List<OidcRp> rps) {
    this.rps = rps;
  }

  /**
   * Returns the logotype for the given RP.
   *
   * @param rpSuffix the RP path suffix
   * @return an SVG image
   */
  @GetMapping(value = "/{rpSuffix}/logo.svg")
  public ResponseEntity<String> getLogo(@PathVariable("rpSuffix") @Nonnull final String rpSuffix) {
    final OidcRp rp = this.rps.stream()
        .filter(r -> rpSuffix.equals(r.getPathSuffix()))
        .findFirst()
        .orElseThrow(() -> new NotFoundException("No OIDC RP with path suffix '%s'".formatted(rpSuffix)));

    return ResponseEntity.ok()
        .header("Cache-Control", "no-cache, no-store")
        .contentType(MediaType.valueOf("image/svg+xml"))
        .body(this.renderLogo(rp.getPathSuffix()));
  }

  /**
   * Renders the logotype - the mosaic followed by the RP name - as an SVG document.
   *
   * @param label the RP name to write next to the mosaic
   * @return the SVG document
   */
  @Nonnull
  private String renderLogo(@Nonnull final String label) {
    final double width = TEXT_X + label.length() * (FONT_SIZE * 0.6) + 16;
    return """
        <svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="64" viewBox="0 0 %.0f 64">
        %s
        <text x="%.0f" y="42" font-family="sans-serif" font-size="%.0f" fill="#2B2A29">%s</text>
        </svg>
        """.formatted(width, width, MOSAIC, TEXT_X, FONT_SIZE, escapeXml(label));
  }

  @Nonnull
  private static String escapeXml(@Nonnull final String text) {
    return text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;");
  }

}