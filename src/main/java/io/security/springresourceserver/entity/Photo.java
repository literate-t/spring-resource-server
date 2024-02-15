package io.security.springresourceserver.entity;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Photo {

  private String userId;
  private String id;
  private String title;
  private String description;
}
