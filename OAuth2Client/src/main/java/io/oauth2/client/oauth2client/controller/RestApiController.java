package io.oauth2.client.oauth2client.controller;

import entity.Photo;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import token.AccessToken;

@RestController
@RequiredArgsConstructor
public class RestApiController {

  private final RestTemplate restTemplate;

  @GetMapping("/token")
  public OAuth2AccessToken token(
      @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient oAuth2AuthorizedClient) {
    return oAuth2AuthorizedClient.getAccessToken();
  }

  @GetMapping("/photos")
  public List<Photo> photos(AccessToken accessToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.add("Authorization", "Bearer " + accessToken.getToken());
    HttpEntity<?> requestEntity = new HttpEntity<>(headers);
    String url = "http://localhost:8082/photos";

    ResponseEntity<List<Photo>> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity,
        new ParameterizedTypeReference<>() {
        });

    return response.getBody();
  }
}
