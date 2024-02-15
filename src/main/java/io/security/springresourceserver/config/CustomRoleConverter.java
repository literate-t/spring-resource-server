package io.security.springresourceserver.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

  private final String PREFIX = "ROLE_";

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {

    String scope = jwt.getClaimAsString("scope");
    Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

    if (null == scope || null == realmAccess) {
      return Collections.emptyList();
    }

    List<GrantedAuthority> authorities1 = Arrays.stream(scope.split(" "))
        .map(roleName -> PREFIX + roleName)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());

    Collection<String> roles = (List<String>) realmAccess.get("roles");
    Collection<GrantedAuthority> authorities2 = roles.stream().map(roleName -> PREFIX + roleName)
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());

    authorities1.addAll(authorities2);

    return authorities1;
  }
}
