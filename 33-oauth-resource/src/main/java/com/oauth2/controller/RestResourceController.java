package com.oauth2.controller;

import com.oauth2.resource.UserInfo;
import com.oauth2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.HashMap;
import java.util.Map;

@Controller
public class RestResourceController {

//	@Autowired
//	UserDetailsService userDetailsService;

	@RequestMapping("/resource")
	@ResponseBody
	public ResponseEntity<HashMap<String, Object>> profile() {
//		SecurityContext context = SecurityContextHolder.getContext();
//		Authentication authentication = context.getAuthentication();
		HashMap<String, Object> map = new HashMap<>();
		map.put("resource","资源");

		return ResponseEntity.ok(map);
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
	RequestMappingHandlerMapping requestMappingHandlerMapping;

	@ResponseBody
	@RequestMapping("/allUrl")
	public Map<RequestMappingInfo, HandlerMethod> url() {
		Map<RequestMappingInfo, HandlerMethod> handlerMethods = requestMappingHandlerMapping.getHandlerMethods();

		return handlerMethods;
	}
}
