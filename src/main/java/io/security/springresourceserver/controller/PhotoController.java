package io.security.springresourceserver.controller;

import io.security.springresourceserver.entity.Photo;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

  @GetMapping("/photos/1")
  public Photo photo1() {
    return Photo.builder()
        .userId("user1")
        .id("1")
        .description("photo 1 desc")
        .title("photo1 title")
        .build();
  }

  @GetMapping("/photos/2")
  // OAuth2ResourceServer의 설정보다 우선한다
  // 설정에선 permitAll()
  @PreAuthorize("hasAuthority('SCOPE_photo')")
  public Photo photo2() {
    return Photo.builder()
        .userId("user2")
        .id("2")
        .description("photo 2 desc")
        .title("photo2 title")
        .build();
  }

  @GetMapping("/photos/3")
  public Photo photo3() {
    return Photo.builder()
        .userId("user2")
        .id("2")
        .description("photo 2 desc")
        .title("photo2 title")
        .build();
  }
}
