package io.security.springresourceserver.controller;

import java.net.URISyntaxException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
  @GetMapping("/")
  public String index() {
    return "index";
  }

  @GetMapping("/api/user")
  public Authentication apiUser(Authentication authentication,
      @AuthenticationPrincipal Jwt principal) throws URISyntaxException {

    JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
    String sub = (String) authenticationToken.getTokenAttributes().get("sub");
    String email = (String) authenticationToken.getTokenAttributes().get("email");
    Object scope = authenticationToken.getTokenAttributes().get("scope");

    Object sub1 = principal.getClaim("sub");
    String token = principal.getTokenValue();

    // token을 가지고 다른 서버와의 통신에도 사용할 수 있다
//    RestTemplate restTemplate = new RestTemplate();
//    HttpHeaders headers = new HttpHeaders();
//    headers.add("Authorization", "Bearer " + token);
//    RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET,
//        new URI("http://localhost:8082"));
//    ResponseEntity<String> response = restTemplate.exchange(request, String.class);
//    String body = response.getBody();

    return authentication;
  }
}
