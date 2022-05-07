package com.example.springsecurity.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ServletRequestAttributes attrs = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attrs.getRequest();

        System.out.println("登录用户："+username+"   ********"+request.getRequestURI());
        SimpleGrantedAuthority role1 = new SimpleGrantedAuthority("role1");
        List<SimpleGrantedAuthority> list = new ArrayList<>();
        list.add(role1);
        return new User("user","$2a$10$kflgQLFt7PQa538CxtF1TOeXrohWiazvrm3tFFi1Syr5b633J8GgG",list);
    }

    public static void main(String[] args) {
        String encode = new BCryptPasswordEncoder().encode("1234");
        System.out.println(encode);
    }
}
