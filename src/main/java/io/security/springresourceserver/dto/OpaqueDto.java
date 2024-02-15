package io.security.springresourceserver.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;

@Setter
@Getter
public class OpaqueDto {

  private boolean active;
  private Authentication authentication;
  private Object principal;
}
