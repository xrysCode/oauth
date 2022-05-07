package oauth2.client1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;

@SpringBootApplication
@EnableOAuth2Sso
public class OauthClient1 {
    public static void main(String[] args) {
        SpringApplication.run(OauthClient1.class,args);
    }
}
