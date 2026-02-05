package se.swedenconnect.testclient.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
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
public class SignatureParameterModel {
  @SerializedName("tbs_data")
  private String tbsData;
  @SerializedName("sign_message")
  private OidcMessageParameterModel signMessage;
  private Boolean requestBody;
  private Boolean valuePresent;
}
