package com.example.springsecurity.config;

import cn.hutool.core.bean.BeanUtil;
import com.example.springsecurity.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.log.LogMessage;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Configuration
@EnableWebSecurity(debug = true)
@Slf4j
@EnableGlobalAuthentication
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        HttpSecurity http1 = http.authorizeRequests()
                .antMatchers("/", "/home","/*/login.html")
                .permitAll()
                .anyRequest()
                .authenticated()
//                .accessDecisionManager()
                .and();

        FormLoginConfigurer<HttpSecurity> formLoginConfigurer = http1.formLogin()
                .loginPage("/{frontOrBack}/login.html")
                .loginProcessingUrl("/{frontOrBack}/login-check")
                .failureUrl("/user/login?error=failureUrl")
                .failureForwardUrl("/user/login?error=failureForwardUrl")
                .successForwardUrl("/success?successForwardUrl")
                .permitAll();
        formLoginConfigurer.addObjectPostProcessor(new ObjectPostProcessor<LoginUrlAuthenticationEntryPoint>() {
                    @Override
                    public LoginUrlAuthenticationEntryPoint postProcess(LoginUrlAuthenticationEntryPoint point) {
                        MyLoginUrlAuthenticationEntryPoint authenticationEntryPoint = new MyLoginUrlAuthenticationEntryPoint(point.getLoginFormUrl());
                        BeanUtil.copyProperties(point,authenticationEntryPoint);
                        return authenticationEntryPoint;
                    }
                });
        HttpSecurity http2 = formLoginConfigurer.and();
        http2.logout()
                .permitAll()

        ;

    }


    public class MyLoginUrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint{
        public MyLoginUrlAuthenticationEntryPoint(String loginFormUrl) {
            super(loginFormUrl);
        }

        @Override
        protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
//                ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
//                HttpServletRequest request = attrs.getRequest();
//                {frontOrBack}
            SecurityContext securityContext = SecurityContextHolder.getContext();
            Authentication authentication = securityContext.getAuthentication();
//            Object principal = authentication.getPrincipal();

            Map<String,String> attributeMap = (Map) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
//            String frontOrBack = attributeMap.get("frontOrBack");
            String loginFormUrl = getLoginFormUrl();
            String newUrl = loginFormUrl.replace("{frontOrBack}", "back");
            return newUrl;
        }

    }

//    @Bean
//    public ExceptionTranslationFilter exceptionTranslationFilter(LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint){
//        return new ExceptionTranslationFilter(loginUrlAuthenticationEntryPoint);
//    }

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
