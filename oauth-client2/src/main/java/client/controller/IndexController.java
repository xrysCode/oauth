package client.controller;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class IndexController {


    @GetMapping("/")
    public Map<String,String> index(@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient client){
        return Collections.singletonMap("hello","oauth2.0");
    }
}
