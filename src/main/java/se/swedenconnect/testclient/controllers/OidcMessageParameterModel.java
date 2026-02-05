package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OidcMessageParameterModel {
  @JsonProperty("message#sv")
  private String messageSwedish;
  @JsonProperty("message#en")
  private String messageEnglish;
  @JsonProperty("message#de")
  private String messageGerman;
  @JsonProperty("message#fr")
  private String messageFrench;
  @JsonProperty("message#it")
  private String messageItalian;
  @JsonProperty("message#es")
  private String messageSpanish;
  @JsonProperty("message#xx")
  private String messageDummy;
  @JsonProperty("message")
  private String message;
  @JsonProperty("mime_type")
  private String mimeType;
  private Boolean requestBody;
  private Boolean valuePresent;
}
