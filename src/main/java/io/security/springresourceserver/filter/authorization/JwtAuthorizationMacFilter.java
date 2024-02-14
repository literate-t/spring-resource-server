package io.security.springresourceserver.filter.authorization;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthorizationMacFilter extends OncePerRequestFilter {

  private final OctetSequenceKey jwk;

  // RSA 검증 때도 사용되는 공통 클래스가 아니기 때문에 OctetSequenceKey으로 받아도 된다
  public JwtAuthorizationMacFilter(OctetSequenceKey jwk) {
    this.jwk = jwk;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authHeader = request.getHeader("Authorization");

    if (null == authHeader || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);

      return;
    }

    // verify token
    String token = authHeader.replace("Bearer ", "");
    SignedJWT signedJWT;

    try {
      signedJWT = SignedJWT.parse(token);
      MACVerifier macVerifier = new MACVerifier(jwk.toSecretKey());
      boolean verified = signedJWT.verify(macVerifier);

      // authentication
      if (verified) {
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        String username = jwtClaimsSet.getClaim("username").toString();
        List<String> authorities = (List<String>) jwtClaimsSet.getClaim("authority");

        if (null != username) {
          UserDetails user = User.withUsername(username)
              .password(UUID.randomUUID().toString())
              .authorities(authorities.get(0))
              .build();

          Authentication authentication = new UsernamePasswordAuthenticationToken(user, null,
              user.getAuthorities());

          SecurityContextHolder.getContext().setAuthentication(authentication);
        }
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    filterChain.doFilter(request, response);
  }
}
