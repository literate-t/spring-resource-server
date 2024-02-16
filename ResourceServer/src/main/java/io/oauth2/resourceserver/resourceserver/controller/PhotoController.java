package io.oauth2.resourceserver.resourceserver.controller;

import io.oauth2.resourceserver.resourceserver.entity.Photo;
import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

  @GetMapping("/photos")
  public List<Photo> photoList() {

    Photo photo1 = getPhoto("1 ", "1Title ", "Desc1 ", "User1 ");
    Photo photo2 = getPhoto("2 ", "2Title ", "Desc2 ", "User2 ");

    return Arrays.asList(photo1, photo2);
  }

  @GetMapping("/remotePhotos")
  public List<Photo> remotePhotoList() {

    Photo photo1 = getPhoto("Remote1 ", "Remote1Title ", "Remote1desc ",
        "RemoteUser1");
    Photo photo2 = getPhoto("Remote2 ", "Remote2Title ", "Remote2desc ",
        "RemoteUser2 ");

    return Arrays.asList(photo1, photo2);
  }

  private Photo getPhoto(String photoId, String title, String desc, String userId) {
    return Photo.builder()
        .id(photoId)
        .title(title)
        .description(desc)
        .userId(userId)
        .build();
  }
}
