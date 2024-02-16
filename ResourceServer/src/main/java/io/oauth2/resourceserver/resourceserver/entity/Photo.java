package io.oauth2.resourceserver.resourceserver.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class Photo {

  private String id;
  private String userId;
  private String title;
  private String description;
}
