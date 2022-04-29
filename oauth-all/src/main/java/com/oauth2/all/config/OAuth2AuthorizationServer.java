package com.oauth2.all.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security)
            throws Exception {
        //Spring Security OAuth2会公开了两个端点，用于检查令牌（/oauth/check_token和/oauth/token_key），
        // 这些端点默认受保护denyAll()。tokenKeyAccess（）和checkTokenAccess（）方法会打开这些端点以供使用。
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
        clients
//                .withClientDetails()
                .inMemory().withClient("clientapp")
                .secret(passwordEncoder.encode("1234"))//$2a$10$WvsS0sT/JiD9hsPhh45hoOmrZYCerSdD3OhaUXC73SonfWvlhonVK
                //authorization_code，password，client_credentials，implicit，或refresh_token。
                .authorizedGrantTypes("password", "authorization_code","refresh_token","client_credentials"/*,"implicit"*/)
                .authorities("READ_ONLY_CLIENT")
                .scopes("read_user_info")
                .resourceIds("oauth2-resource")//authorities - 授予客户的权限（常规Spring Security权限）。
                .redirectUris("http://localhost:8081/login")//redirectUris - 将用户代理重定向到客户端的重定向端点。它必须是绝对URL。
                .accessTokenValiditySeconds(50000)
                .refreshTokenValiditySeconds(50000)
                .autoApprove(true)
//                .and()
//                .withClient()

        ;
    }
}