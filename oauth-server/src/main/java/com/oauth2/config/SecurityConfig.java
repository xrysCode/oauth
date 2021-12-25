package com.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @ClassName: SecurityConfig
 * @Description:TODO(这里用一句话描述这个类的作用)
 * @author: wanghao
 * @date: 2019年8月15日 下午1:54:46
 * @version V1.0
 * 
 */
@Configuration
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/**")
				.requestMatchers()
				.antMatchers("/oauth/authorize**", "/login**", "/error**")
			.and()
				.authorizeRequests().anyRequest().authenticated()
			.and()
				.formLogin().permitAll();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.inMemoryAuthentication().withUser("peterwanghao")
				.password(passwordEncoder().encode("123456")).roles("USER");
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
