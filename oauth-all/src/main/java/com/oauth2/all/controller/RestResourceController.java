package com.oauth2.all.controller;

import com.oauth2.all.entity.UserInfoEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class RestResourceController {
	@RequestMapping("/api/users/me")
	public ResponseEntity<UserInfoEntity> profile() {
		User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String email = user.getUsername() + "@126.com";

		UserInfoEntity profile = new UserInfoEntity();
		profile.setName(user.getUsername());
		profile.setEmail(email);
		System.err.println("用户信息");
		return ResponseEntity.ok(profile);
	}

	@RequestMapping("/api/users/me1")
	public ResponseEntity<Authentication> profile1() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		String email = user.getUsername() + "@126.com";
//
//		UserInfoEntity profile = new UserInfoEntity();
//		profile.setName(user.getUsername());
//		profile.setEmail(email);
		System.err.println("用户信息Authentication");
		return ResponseEntity.ok(authentication);
	}
}
