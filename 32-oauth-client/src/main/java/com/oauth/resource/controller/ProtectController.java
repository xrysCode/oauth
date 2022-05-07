package com.oauth.resource.controller;

import org.springframework.security.config.web.servlet.oauth2.resourceserver.OAuth2ResourceServerSecurityMarker;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author xry
 * @Date 2021/12/27 16:05
 */
@RestController
@OAuth2ResourceServerSecurityMarker
public class ProtectController {
    @RequestMapping("/protect")
    public Map<String,String> test(){
        HashMap<String, String> map = new HashMap<>();
        map.put("protect","protect11");
        return map;
    }
}
