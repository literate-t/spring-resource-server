package io.security.springresourceserver.signature;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import java.security.PrivateKey;
import org.springframework.security.core.userdetails.UserDetails;

public class RsaPublicKeySecuritySigner extends SecuritySigner {

  private PrivateKey privateKey;

  @Override
  public String getJwtToken(UserDetails user, JWK jwk) throws JOSEException {

    RSASSASigner jwsSigner = new RSASSASigner(privateKey);

    return getJwtTokenInternal(jwsSigner, user, jwk);
  }

  public void setPrivateKey(PrivateKey privateKey) {
    this.privateKey = privateKey;
  }
}
