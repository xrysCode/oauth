package com.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author xry
 * @Date 2022/4/27 19:30
 */
@RestController
@RequestMapping("user")
public class UserController {
    @RequestMapping("info")
    public Object o(Authentication authentication){
        System.err.println("====");
        return authentication;
    }
}
