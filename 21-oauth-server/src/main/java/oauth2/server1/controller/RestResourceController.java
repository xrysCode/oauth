package oauth2.server1.controller;

import oauth2.server1.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Map;

@Controller
public class RestResourceController {

	@Autowired
	UserDetailsService userDetailsService;

	@RequestMapping("/api/users/me")
	public ResponseEntity<UserDetails> profile() {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		String principal = (String) authentication.getPrincipal();
//		User user = (User) authentication.getPrincipal();
		UserDetails userDetails = userDetailsService.loadUserByUsername(principal);


//		String email = user.getUsername() + "@126.com";

//		UserInfo profile = new UserInfo();
//		profile.setName(user.getUsername());
//		profile.setEmail(email);

		return ResponseEntity.ok(userDetails);
	}
//	@GetMapping("/login")
//	public String login() {
//		return "login.html";
//	}
//	@PostMapping("/login")
//	public String login(String username,String password) {
//		return "login.html";
//	}

	@Autowired
	UserService userService;

	@PostMapping("/user/login")
	public UserDetails login(String username, String password,String other) {
		UserDetails userDetails = userService.loadUserByUsername(username);

		return userDetails;
	}

	@Autowired
	RequestMappingHandlerMapping requestMappingHandlerMapping;

	@ResponseBody
	@RequestMapping("/allUrl")
	public Map<RequestMappingInfo, HandlerMethod> url() {
		Map<RequestMappingInfo, HandlerMethod> handlerMethods = requestMappingHandlerMapping.getHandlerMethods();

		return handlerMethods;
	}
}
