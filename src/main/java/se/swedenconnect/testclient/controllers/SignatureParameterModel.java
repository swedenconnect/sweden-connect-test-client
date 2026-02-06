package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nimbusds.jose.shaded.gson.annotations.SerializedName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class SignatureParameterModel {
  @SerializedName("tbs_data")
  private String tbsData;
  @SerializedName("sign_message")
  private OidcMessageParameterModel signMessage;
  private Boolean requestBody;
  private Boolean valuePresent;
  private Boolean b64Encode;

  @JsonIgnore
  public String getPreferredMessage() {
    if (Objects.nonNull(this.signMessage)) {
      return Stream.of(
              this.signMessage.getMessage(),
              this.signMessage.getMessageSwedish(),
              this.signMessage.getMessageEnglish(),
              this.signMessage.getMessageGerman(),
              this.signMessage.getMessageFrench(),
              this.signMessage.getMessageItalian(),
              this.signMessage.getMessageSpanish(),
              this.signMessage.getMessageDummy()
          ).filter(Objects::nonNull)
          .findFirst()
          .orElse("");
    }
    return "";
  }
}
