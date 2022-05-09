package com.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class Oauth2Resource2 {
    static ConfigurableApplicationContext run ;
    public static void main(String[] args) {
        run = SpringApplication.run(Oauth2Resource2.class, args);
        System.out.println("----");
    }

//    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
