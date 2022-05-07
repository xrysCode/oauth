package com.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.ArrayList;

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
//                .tokenKeyAccess("permitAll()")
                .tokenKeyAccess("isAuthenticated()")//获取秘钥需要身份认证，使用单点登录时必须配置
//                .checkTokenAccess("isAuthenticated()")
//                .allowFormAuthenticationForClients()

        ;
//        security.tokenKeyAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
        clients
//                .withClientDetails()
                .inMemory()
                .withClient("clientapp")
                .secret(passwordEncoder.encode("1234"))
                .authorizedGrantTypes("password", "authorization_code","refresh_token")
                .authorities("READ_ONLY_CLIENT")
                .scopes("read_user_info")
                .resourceIds("oauth2-resource")//authorities - 授予客户的权限（常规Spring Security权限）。
                .redirectUris("http://localhost:9001/login","http://localhost:8080/foo/bar",
                        "http://localhost:8989/**"
                )//redirectUris - 将用户代理重定向到客户端的重定向端点。它必须是绝对URL。
                .additionalInformation("a:aa","bb")
                .accessTokenValiditySeconds(50000)
                .refreshTokenValiditySeconds(50000)
                .autoApprove(true)

                .and()
                .withClient("auth")
                .secret(passwordEncoder.encode("111"))
                .authorizedGrantTypes("password", "authorization_code","refresh_token")
//                .authorities("READ_ONLY_CLIENT")
                .scopes("read_user_info")
//                .scopes(ClientConstants.scope)
                .autoApprove(true)
                .accessTokenValiditySeconds(86400)
                .refreshTokenValiditySeconds(86400)
                .resourceIds("oauth2-resource-id")//authorities - 授予客户的权限（常规Spring Security权限）。
                .redirectUris("http://localhost:8989/doc.html")//redirectUris - 将用户代理重定向到客户端的重定向端点。它必须是绝对URL。
        ;
    }
    @Autowired
    UserDetailsService userDetailsService1;
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
        ArrayList<TokenEnhancer> tokenEnhancers = new ArrayList<>();
        tokenEnhancers.add(myTokenEnhancer());
        tokenEnhancers.add(accessTokenConverter());
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancers);

        endpoints.tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                .accessTokenConverter(accessTokenConverter())//.setClientDetailsService()

//                .tok
                .userDetailsService(userDetailsService1)
        ;
    }

    @Bean
    public MyTokenEnhancer myTokenEnhancer(){
       return new MyTokenEnhancer();
    }

    @Bean
    public TokenStore tokenStore(){
        return new JwtTokenStore(accessTokenConverter());
    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        converter.setKeyPair(keyPair());
        return converter;
    }

    @Autowired
    public void myAuthenticationManagerBuilder(AuthenticationManagerBuilder authenticationManagerBuilder, UserDetailsService userDetailsService1) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService1);
    }

}