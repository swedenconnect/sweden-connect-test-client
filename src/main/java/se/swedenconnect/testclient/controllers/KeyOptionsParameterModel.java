package se.swedenconnect.testclient.controllers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class KeyOptionsParameterModel {
  private String signKey;
  private String encKey;
  private List<KeyModel> signKeys;
  private List<KeyModel> encKeys;
  private Boolean moduleEnabled;
}
