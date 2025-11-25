package se.swedenconnect.testclient.controllers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Optional;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class ModelParameter {
  private String value;
  private Boolean requestBody;
  private Boolean valuePresent;
}
