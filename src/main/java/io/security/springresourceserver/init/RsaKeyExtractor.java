package io.security.springresourceserver.init;

import io.security.springresourceserver.signature.RsaPublicKeySecuritySigner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class RsaKeyExtractor implements ApplicationRunner {

  private final RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner;


  @Override
  public void run(ApplicationArguments args) throws Exception {
    String path = "D:\\source codes\\inflearn\\spring-resource-server\\src\\main\\resources\\cert\\";
    String keyAlias = "apiKey";
    File file = new File(path + "publicKey.txt");
    char[] pass = "pass1234".toCharArray();

    FileInputStream is = new FileInputStream(path + "apiKey.jks");
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(is, pass);
    Key key = keyStore.getKey(keyAlias, pass);

    if (key instanceof PrivateKey) {

      Certificate certificate = keyStore.getCertificate(keyAlias);
      PublicKey publicKey = certificate.getPublicKey();
      KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
      rsaPublicKeySecuritySigner.setPrivateKey(keyPair.getPrivate());

      if (!file.exists()) {
        String publicStr = Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
        publicStr =
            "-----BEGIN PUBLIC KEY-----" + "\r\n" + publicStr + "\r\n" + "-----END PUBLIC KEY-----";

        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(file),
            Charset.defaultCharset());
        writer.write(publicStr);
        writer.close();
      }
    }

    is.close();
  }
}
