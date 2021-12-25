package com.example.springsecurity.config;

import com.example.springsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
        http.authorizeRequests()
                .antMatchers("/","/home").permitAll()
                .anyRequest().authenticated()
//                .accessDecisionManager()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout().permitAll();
    }

    @Bean
    public PasswordEncoder bCryptPasswordEncoder(){
        log.warn("------------------密码解密------------");
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
//        auth.inMemoryAuthentication().withUser("user").password("1234").roles("USER");
    }

    @Override
    public void configure(WebSecurity web)  {
//        super.configure(web);
        web.ignoring().antMatchers("/ig.html");
    }
}
