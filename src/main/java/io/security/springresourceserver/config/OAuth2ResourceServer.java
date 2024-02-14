package io.security.springresourceserver.config;

import com.nimbusds.jose.jwk.OctetSequenceKey;
import io.security.springresourceserver.filter.authentication.JwtAuthenticationFilter;
import io.security.springresourceserver.filter.authorization.JwtAuthorizationMacFilter;
import io.security.springresourceserver.signature.MacSecuritySigner;
import javax.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServer {
  private final AuthenticationConfiguration authenticationConfiguration;
  private final MacSecuritySigner macSecuritySigner;
  private final OctetSequenceKey octetSequenceKey;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // token으로 검증하는 것이기 때문에
    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.authorizeRequests(registry -> registry.antMatchers("/").permitAll());
    http.userDetailsService(userDetailsService());
    http.addFilterBefore(jwtAuthenticationFilter(macSecuritySigner, octetSequenceKey),
        UsernamePasswordAuthenticationFilter.class);
    http.addFilterBefore(jwtAuthorizationMacFilter(octetSequenceKey),
        UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) {
    return new JwtAuthorizationMacFilter(octetSequenceKey);
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
      throws Exception {
    // AuthenticationConfiguration에 있는 getAuthenticationManager()를 그대로 가져다 쓴다
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public Filter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner,
      OctetSequenceKey octetSequenceKey) throws Exception {
    // 최상위 부모가 AbstractAuthenticationProcessingFilter인데 여기에서 Authentication Manager를 요청
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(macSecuritySigner,
        octetSequenceKey);
    jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));

    return jwtAuthenticationFilter;
  }

  // make a test user
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();

    return new InMemoryUserDetailsManager(user);
  }

  // for dev test
  @Bean
  @SuppressWarnings("deprecation")
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }
}

