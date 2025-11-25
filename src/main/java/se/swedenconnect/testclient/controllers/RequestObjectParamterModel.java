package se.swedenconnect.testclient.controllers;

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
public class RequestObjectParamterModel {
  private ModelParameter issuer;
  private ModelParameter audience;
  private Boolean signRequest;
  private Boolean encryptRequest;
  private Boolean moduleEnabled;
}
