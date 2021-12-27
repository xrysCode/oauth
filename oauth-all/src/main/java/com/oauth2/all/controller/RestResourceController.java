package com.oauth2.all.controller;

import com.oauth2.all.entity.UserInfoEntity;
import org.springframework.http.ResponseEntity;
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

		return ResponseEntity.ok(profile);
	}
}
