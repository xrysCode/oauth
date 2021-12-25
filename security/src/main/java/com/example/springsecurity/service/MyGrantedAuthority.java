package com.example.springsecurity.service;

import org.springframework.security.core.GrantedAuthority;

public class MyGrantedAuthority implements GrantedAuthority {
    @Override
    public String getAuthority() {
        return null;
    }
}
