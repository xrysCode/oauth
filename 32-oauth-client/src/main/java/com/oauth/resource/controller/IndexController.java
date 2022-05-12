package com.oauth.resource.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.MultiValueMapAdapter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;


import java.net.URI;
import java.util.Collections;
import java.util.Map;

@RestController
public class IndexController {


    @GetMapping("/")
    public Map<String,String> index(){
        return Collections.singletonMap("hello","oauth2.0");
    }
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user")
    public OidcUserInfo user(Authentication authentication){
        OAuth2AuthorizedClient authorizedClient =
                this.authorizedClientService.loadAuthorizedClient("clientapp", authentication.getName());

//        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//        SecurityContextHolder.
        SecurityContext context = SecurityContextHolder.getContext();
        OidcUserInfo userInfo = ((DefaultOidcUser) context.getAuthentication().getPrincipal()).getUserInfo();
        return userInfo;
    }

//    @Autowired
//    RestTemplate restTemplate;
    @GetMapping("/user2")
    public Authentication user2(Authentication authentication){
        OAuth2AuthorizedClient authorizedClient =
                this.authorizedClientService.loadAuthorizedClient("clientapp", authentication.getName());

//        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//        SecurityContextHolder.
        SecurityContext context = SecurityContextHolder.getContext();
        MultiValueMap<String, String> headers=new LinkedMultiValueMap();
        OAuth2AccessToken.TokenType bearer = OAuth2AccessToken.TokenType.BEARER;
//        urlConnection.getHeaderField("WWW-Authenticate");
        headers.add("Authorization",bearer.getValue()+" "+"");
        RequestEntity requestEntity = new RequestEntity(headers,HttpMethod.GET,  URI.create("http://localhost:9050/userDetails"));
        ResponseEntity<Map> forEntity = new RestTemplate().exchange(requestEntity, Map.class);
        return context.getAuthentication();
    }
}
