package se.swedenconnect.testclient.controllers;

import com.nimbusds.jose.shaded.gson.TypeAdapter;
import com.nimbusds.jose.shaded.gson.stream.JsonReader;
import com.nimbusds.jose.shaded.gson.stream.JsonWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class OidcMessageSerializer extends TypeAdapter<OidcMessageParameterModel> {

  @Override
  public void write(JsonWriter out, OidcMessageParameterModel value) throws IOException {
    if (value == null) {
      out.nullValue();
      return;
    }

    out.beginObject();

    writeEncoded(out, "message#sv", value.getMessageSwedish());
    writeEncoded(out, "message#en", value.getMessageEnglish());
    writeEncoded(out, "message#de", value.getMessageGerman());
    writeEncoded(out, "message#fr", value.getMessageFrench());
    writeEncoded(out, "message#es", value.getMessageSpanish());
    writeEncoded(out, "message#xx", value.getMessageDummy());
    writeEncoded(out, "message", value.getMessage());

    out.name("mime_type").value(value.getMimeType());

    out.endObject();
  }

  private void writeEncoded(JsonWriter out, String name, String value) throws IOException {
    if (value != null) {
      out.name(name)
          .value(Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
    }
  }

  @Override
  public OidcMessageParameterModel read(JsonReader in) {
    throw new UnsupportedOperationException("Deserialization not supported");
  }
}
