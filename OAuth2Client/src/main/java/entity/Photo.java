package entity;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Photo {

  private String id;
  private String userId;
  private String title;
  private String description;
}
