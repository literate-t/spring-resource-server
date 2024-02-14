package io.security.springresourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.security.springresourceserver.signature.MacSecuritySigner;
import io.security.springresourceserver.signature.RsaSecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// for sign and verification
@Configuration
public class SignatureConfig {

  @Bean
  public MacSecuritySigner macSecuritySigner() {
    return new MacSecuritySigner();
  }

  @Bean
  public OctetSequenceKey octetSequenceKey() throws JOSEException {
    OctetSequenceKey octetSequenceKey = new OctetSequenceKeyGenerator(256)
        .keyID("mackey")
        .algorithm(JWSAlgorithm.HS256)
        .generate();

    return octetSequenceKey;
  }

  @Bean
  public RsaSecuritySigner rsaSecuritySigner() {
    return new RsaSecuritySigner();
  }

  @Bean
  public RSAKey rsaKey() throws JOSEException {
    RSAKey rsaKey = new RSAKeyGenerator(2048)
        .keyID("rsaKey")
        .algorithm(JWSAlgorithm.RS512)
        .generate();

    return rsaKey;
  }
}
