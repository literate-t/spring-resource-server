package io.security.springresourceserver.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuth2ResourceServerConfig {

  private final OAuth2ResourceServerProperties properties;

  public OAuth2ResourceServerConfig(OAuth2ResourceServerProperties properties) {
    this.properties = properties;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests(registry -> registry.anyRequest().authenticated());
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    return http.build();
  }

  @Bean
  public JwtDecoder jwtDecoder1() {
    return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
  }

  @Bean
  public JwtDecoder jwtDecoder2() {
    return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
  }

  @Bean
  public JwtDecoder jwtDecoder3() {
    return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri()).jwsAlgorithm(
        SignatureAlgorithm.RS512).build(); // RS256 is default
  }
}
