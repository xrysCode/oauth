package server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.RequestContextHolder;
import server.config.AuthorizationServerConfiguration2;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Collections;
import java.util.Map;

@Controller
public class UserInfoController {


    @GetMapping("/")
    @ResponseBody
    public Map<String,String> index(){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient server
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        RequestContextHolder.getRequestAttributes().getSessionId();
        return Collections.singletonMap("hello","oauth2.0");
    }

    @GetMapping("/userDetails")
    @ResponseBody
    public Object login(HttpServletRequest request){//@RegisteredOAuth2AuthorizedClient("clientapp") OAuth2AuthorizedClient server
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        HttpSession session = request.getSession(false);
        Object user = ((BearerTokenAuthentication) authentication).getTokenAttributes().get(StandardClaimNames.SUB);
        Object o = AuthorizationServerConfiguration2.cacheMap.get(user);
        return o;
    }
}
