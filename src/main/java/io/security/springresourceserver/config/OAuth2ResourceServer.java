package io.security.springresourceserver.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.springresourceserver.filter.authentication.JwtAuthenticationFilter;
import io.security.springresourceserver.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import io.security.springresourceserver.signature.MacSecuritySigner;
import io.security.springresourceserver.signature.RsaPublicKeySecuritySigner;
import io.security.springresourceserver.signature.RsaSecuritySigner;
import io.security.springresourceserver.signature.SecuritySigner;
import javax.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServer {
  private final AuthenticationConfiguration authenticationConfiguration;
  private final MacSecuritySigner macSecuritySigner;
  private final OctetSequenceKey octetSequenceKey;
  private final RsaSecuritySigner rsaSecuritySigner;
  private final RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner;
  private final RSAKey rsaKey;
  private final JwtDecoder jwtDecoder;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // token으로 검증하는 것이기 때문에
    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    http.authorizeRequests(registry -> registry.antMatchers("/").permitAll());
    http.userDetailsService(userDetailsService());
//    http.addFilterBefore(jwtAuthenticationFilter(rsaPublicKeySecuritySigner, rsaKey),
//        UsernamePasswordAuthenticationFilter.class);

    // 내부적으로 JwtConfigurer 객체에서 JwtDecoder를 가져와서 처리한다
    // Spring에게 맡기기
    // application.yml에 jwk-set-uri을 설정함
    http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//    http.addFilterBefore(jwtAuthorizationRsaFilter(rsaKey),
//        UsernamePasswordAuthenticationFilter.class);
//    http.addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(jwtDecoder),
//        UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }

  @Bean
  public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(
      JwtDecoder jwtDecoder) {
    return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
  }

//  @Bean
//  public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey)
//      throws JOSEException {
//    return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
//  }

//  @Bean
//  public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsakey) throws JOSEException {
//    return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsakey.toRSAPublicKey()));
//  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
      throws Exception {
    // AuthenticationConfiguration에 있는 getAuthenticationManager()를 그대로 가져다 쓴다
    return authenticationConfiguration.getAuthenticationManager();
  }

  public Filter jwtAuthenticationFilter(SecuritySigner securitySigner,
      JWK key) throws Exception {
    // 최상위 부모가 AbstractAuthenticationProcessingFilter인데 여기에서 Authentication Manager를 요청
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(securitySigner,
        key);
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

