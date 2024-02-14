package io.security.springresourceserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import io.security.springresourceserver.signature.MacSecuritySigner;
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
}
