package oauth2.server1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

//@Configuration
//@EnableGlobalAuthentication
//@EnableOAuth2Sso
@Order(1)
@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//	@Autowired
//	BCryptPasswordEncoder bCryptPasswordEncoder;
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.antMatcher("/**")
				.requestMatchers()
				.antMatchers("/oauth/authorize**", "/login**", "/error**")
				//requestMatchers().anyRequest()等同于http.authorizeRequests().anyRequest().access(“permitAll”)；
			.and()
				.authorizeRequests().anyRequest().authenticated()
			.and()//.httpBasic()
				.formLogin()
				///*"http://localhost:3000" */ /*"/user/login.html"*/"login.html"
//				.loginPage("/user/login")
				//.failureUrl("/error")
//				.successForwardUrl("")
//				.failureForwardUrl("")
//				.usernameParameter("account")
//				.loginProcessingUrl("/user/login")

				.permitAll()
				;
	}

	@Autowired
	UserDetailsService userDetailsService;
	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
//		auth.inMemoryAuthentication().withUser("user")
//				.password(passwordEncoder().encode("123456")).roles("USER");
		auth.userDetailsService(userDetailsService);
//		auth.authenticationProvider()

	}




}
