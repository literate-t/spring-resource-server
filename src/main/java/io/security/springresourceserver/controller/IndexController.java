package io.security.springresourceserver.controller;

import io.security.springresourceserver.dto.OpaqueDto;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
  @GetMapping("/")
  public Authentication index(Authentication authentication, @AuthenticationPrincipal
  OAuth2AuthenticatedPrincipal principal) {
    BearerTokenAuthentication tokenAuthentication = (BearerTokenAuthentication) authentication;
    Map<String, Object> tokenAttributes = tokenAuthentication.getTokenAttributes();
    boolean active = (boolean) tokenAttributes.get("active");

    OpaqueDto opaqueDto = new OpaqueDto();
    opaqueDto.setActive(active);
    opaqueDto.setAuthentication(authentication);
    opaqueDto.setPrincipal(principal);

    return authentication;
  }
}
