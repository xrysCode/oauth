package com.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


//@Configuration
public class OAuth2ResourceServer  {
//	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
//			.antMatchers("/user/login**","/login","/allUrl","/login.html").permitAll()
				.antMatchers("/").permitAll()
			.antMatchers("/api/**").authenticated()
//			.antMatchers("/**").authenticated()
		;
	}
}
