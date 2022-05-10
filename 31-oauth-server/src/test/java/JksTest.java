import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class JksTest {
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, JOSEException {
        //TODO 这里优化到配置
        String path = "oauthJwt.jks";
        String alias = "oauthJwt";
        String pass = "111111";

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");//KeyStore.getDefaultType()
        char[] pin = pass.toCharArray();
        jks.load(resource.getInputStream(), pin);

        RSAKey rsaKey = RSAKey.load(jks, alias, "123456".toCharArray());

        System.out.println("----------");
    }
}
