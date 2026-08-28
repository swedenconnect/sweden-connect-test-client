package se.swedenconnect.testclient.controllers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class OIDCAuthnRequestParameterModel {
  private String op;
  private String rp;
  private ModelParameter scope;
  private ModelParameter clientId;
  private ModelParameter redirectUri;
  private ModelParameter acrValues;
  private Map<String, Object> claims;
  private Boolean claimInRequestBody;
  private RequestObjectParamterModel requestObject;
  private AdvancedOptionsParamterModel advanced;
  private KeyOptionsParameterModel keys;
  private OidcMessageParameterModel userMessage;
  private SignatureParameterModel signMessage;
}
