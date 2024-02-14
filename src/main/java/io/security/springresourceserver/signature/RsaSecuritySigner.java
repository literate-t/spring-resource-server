package io.security.springresourceserver.signature;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.security.core.userdetails.UserDetails;

public class RsaSecuritySigner extends SecuritySigner {

  @Override
  public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

    RSASSASigner jwsSigner = new RSASSASigner(jwk.toRSAKey().toPrivateKey());

    return getJwtTokenInternal(jwsSigner, user, jwk);
  }
}
