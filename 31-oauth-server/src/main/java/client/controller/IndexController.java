package client.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.Map;

@Controller
public class IndexController {


    @GetMapping("/")
    @ResponseBody
    public Map<String,String> index(){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient client
        return Collections.singletonMap("hello","oauth2.0");
    }

//    @GetMapping("/login")
//    public ModelAndView login(){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient client
//        return "login";
//    }
}
