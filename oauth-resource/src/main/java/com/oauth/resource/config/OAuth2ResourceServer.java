package com.oauth.resource.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
//@EnableResourceServer
public class OAuth2ResourceServer extends WebSecurityConfigurerAdapter {

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests().antMatchers("/public/**").permitAll().anyRequest()
//				.hasRole("USER").and()
//				// Possibly more configuration ...
//				.formLogin() // enable form based log in
//				// set permitAll for all URLs associated with Form Login
//				.permitAll();
//	}

		@Override
	public void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
//				.requestMatchers()
			.antMatchers("/no/protect").permitAll()
			.antMatchers("/api/**").authenticated();
	}


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
				// enable in memory based authentication with a user named "user" and "admin"
				.inMemoryAuthentication().withUser("user").password("password").roles("USER")
				.and().withUser("admin").password("password").roles("USER", "ADMIN");
	}
}