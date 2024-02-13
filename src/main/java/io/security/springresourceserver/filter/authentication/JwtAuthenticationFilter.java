package io.security.springresourceserver.filter.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.springresourceserver.dto.LoginDto;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// Authentication and issuing a token to client
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {

    ObjectMapper objectMapper = new ObjectMapper();
    LoginDto loginDto;

    try {
      loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
        loginDto.getUsername(), loginDto.getPassword());

    return getAuthenticationManager().authenticate(authenticationToken);
  }

  // issue a token
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {

    SecurityContextHolder.getContext().setAuthentication(authResult);
    getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
  }
}
