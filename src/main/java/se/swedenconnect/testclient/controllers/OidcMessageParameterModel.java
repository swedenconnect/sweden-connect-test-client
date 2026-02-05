package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.shaded.gson.annotations.Expose;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
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
  @SerializedName("message#sv")
  private String messageSwedish;
  @JsonProperty("message#en")
  @SerializedName("message#en")
  private String messageEnglish;
  @JsonProperty("message#de")
  @SerializedName("message#de")
  private String messageGerman;
  @JsonProperty("message#fr")
  @SerializedName("message#fr")
  private String messageFrench;
  @JsonProperty("message#it")
  @SerializedName("message#it")
  private String messageItalian;
  @JsonProperty("message#es")
  @SerializedName("message#es")
  private String messageSpanish;
  @JsonProperty("message#xx")
  @SerializedName("message#xx")
  private String messageDummy;
  @JsonProperty("message")
  @SerializedName("message")
  private String message;
  @JsonProperty("mime_type")
  @SerializedName("mime_type")
  private String mimeType;
  private Boolean requestBody;
  private Boolean valuePresent;
}
