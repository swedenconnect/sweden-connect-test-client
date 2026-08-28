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
public class AdvancedOptionsParamterModel {
  private ModelParameter responseType;
  private ModelParameter state;
  private ModelParameter nonce;
  private ModelParameter prompt;
  private ModelParameter loginHint;
  private ModelParameter codeChallengeMethod;
  private ModelParameter codeChallenge;
  private Boolean moduleEnabled;
}
