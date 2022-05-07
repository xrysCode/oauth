package oauth2.server1.config;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

/**
 * @Author xry
 * @Date 2022/4/27 19:45
 */
public class MyTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        HashMap<String, Object> map = new HashMap<>();
        map.put("enhance","enhance-x");
        ((DefaultOAuth2AccessToken)accessToken).setAdditionalInformation(map);
        return accessToken;
    }
}
