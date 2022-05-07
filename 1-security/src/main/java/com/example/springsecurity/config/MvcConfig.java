package com.example.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
//        super.addViewControllers(registry);
        registry.addViewController("/home").setViewName("home1");
        registry.addViewController("/").setViewName("home1");
        registry.addViewController("/hello").setViewName("hello");
//        registry.addViewController("/login").setViewName("login");
//        registry.addViewController("/user/login").setViewName("login");
        registry.addViewController("/{user}/login.html");//.setViewName("login");
    }
}
