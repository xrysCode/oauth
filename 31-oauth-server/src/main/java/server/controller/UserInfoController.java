package server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collections;
import java.util.Map;

@Controller
public class UserInfoController {


    @GetMapping("/")
    @ResponseBody
    public Map<String,String> index(){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient server
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return Collections.singletonMap("hello","oauth2.0");
    }

    @GetMapping("/userInfo1")
    @ResponseBody
    public Object login(){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient server
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        return authentication;
    }
}
