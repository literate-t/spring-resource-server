package io.security.springresourceserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
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
        registry -> registry
            .antMatchers("/photos/1").hasAuthority("ROLE_photo")
            .antMatchers("/photos/3").hasAuthority("ROLE_default-roles-oauth2")
            .anyRequest()
            .authenticated());
    http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
//    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    return http.build();
  }

  @Bean
  public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
    http.authorizeRequests(
        registry -> registry.antMatchers("/photos/2").permitAll().anyRequest()
            .authenticated());
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

    return http.build();
  }
}
