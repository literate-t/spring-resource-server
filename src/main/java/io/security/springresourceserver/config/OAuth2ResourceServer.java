package io.security.springresourceserver.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Opaquetoken;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OAuth2ResourceServer {

  @Bean
  public SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

    JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
    jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConverter());

    http.authorizeRequests(
        registry -> registry.anyRequest().authenticated());
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);

    return http.build();
  }

  @Bean
  public OpaqueTokenIntrospector opaqueTokenIntrospector(
      OAuth2ResourceServerProperties properties) {
    Opaquetoken opaquetoken = properties.getOpaquetoken();

    return new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(),
        opaquetoken.getClientId(), opaquetoken.getClientSecret());
  }
}
