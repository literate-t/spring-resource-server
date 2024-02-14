package io.security.springresourceserver.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public abstract class SecuritySigner {

  public abstract String getJwtToken(UserDetails user, JWK jwk) throws JOSEException;

  protected String getJwtTokenInternal(JWSSigner jwsSigner, UserDetails user, JWK jwk)
      throws JOSEException {
    JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm()).keyID(
        jwk.getKeyID()).build();

    List<String> authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList());
    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
        .subject("user")
        .issuer("http://localhost:8081")
        .claim("username", user.getUsername())
        .claim("authority", authorities)
        .expirationTime(new Date(new Date().getTime() + 1000 * 60 * 5)).build();

    SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
    signedJWT.sign(jwsSigner);
    String jwtToken = signedJWT.serialize();

    return jwtToken;
  }
}
