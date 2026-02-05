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
public class SignatureParameterModel {
  @JsonProperty("tbc_data")
  private String tbsData;
  @JsonProperty("sign_message")
  private OidcMessageParameterModel signMessage;
  private Boolean requestBody;
  private Boolean valuePresent;
}
