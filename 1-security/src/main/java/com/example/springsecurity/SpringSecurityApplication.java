package com.example.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Map;

@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(SpringSecurityApplication.class, args);
        Map<String, LoginUrlAuthenticationEntryPoint> beansOfType = run.getBeansOfType(LoginUrlAuthenticationEntryPoint.class);
        System.out.println("-----------");
    }

}
