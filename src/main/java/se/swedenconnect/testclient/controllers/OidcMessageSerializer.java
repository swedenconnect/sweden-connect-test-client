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

import com.nimbusds.jose.shaded.gson.TypeAdapter;
import com.nimbusds.jose.shaded.gson.stream.JsonReader;
import com.nimbusds.jose.shaded.gson.stream.JsonWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class OidcMessageSerializer extends TypeAdapter<OidcMessageParameterModel> {

  @Override
  public void write(JsonWriter out, OidcMessageParameterModel value) throws IOException {
    if (value == null) {
      out.nullValue();
      return;
    }

    out.beginObject();

    write(out, "message#sv", value.getMessageSwedish(), value.getB64Encode());
    write(out, "message#en", value.getMessageEnglish(), value.getB64Encode());
    write(out, "message#de", value.getMessageGerman(), value.getB64Encode());
    write(out, "message#fr", value.getMessageFrench(), value.getB64Encode());
    write(out, "message#es", value.getMessageSpanish(), value.getB64Encode());
    write(out, "message#xx", value.getMessageDummy(), value.getB64Encode());
    write(out, "message", value.getMessage(), value.getB64Encode());

    out.name("mime_type").value(value.getMimeType());

    out.endObject();
  }

  private void write(JsonWriter out, String name, String value, Boolean encode) throws IOException {
    if (value != null) {
      if (Boolean.TRUE.equals(encode)) {
        out.name(name)
            .value(Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
      } else {
        out.name(name)
            .value(value);
      }

    }
  }

  @Override
  public OidcMessageParameterModel read(JsonReader in) {
    throw new UnsupportedOperationException("Deserialization not supported");
  }
}
