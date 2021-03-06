package server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import server.DT_O1.MyUser;

import java.security.KeyStore;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * The type Authorization server configuration.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity(debug = true)
public class AuthorizationServerConfiguration2 extends OAuth2AuthorizationServerConfiguration {

    @Bean
    UserDetailsService users(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("123"))
//                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
                .roles("r_User")
                .build();
        MyUser myUser = new MyUser("user", passwordEncoder.encode("123"), "xxxx@163.com");
        return new InMemoryUserDetailsManager(myUser);
    }

    @Bean
    JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations,
                                                                  RegisteredClientRepository registeredClientRepository){
        return new JdbcOAuth2AuthorizationService(jdbcOperations,registeredClientRepository);
    }

    @Bean
    JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
                                                                                RegisteredClientRepository registeredClientRepository){
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations,registeredClientRepository);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
//                new OAuth2AuthorizationServerConfigurer<>();
        authorizationServerConfigurer.oidc(oidcConfigurer -> {
           oidcConfigurer.userInfoEndpoint(oidcUserInfoEndpointConfigurer -> {
               oidcUserInfoEndpointConfigurer.userInfoMapper((oidcUserInfoAuthenticationContext)->{
                   OAuth2Authorization authorization = oidcUserInfoAuthenticationContext.getAuthorization();
                   UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = oidcUserInfoAuthenticationContext.getAuthorization().getAttribute("java.security.Principal");
                   Object principal = usernamePasswordAuthenticationToken.getPrincipal();

                   Map<String,Object> map = new HashMap<>();
                   map.put("sub",authorization.getPrincipalName());
                   map.put("principal",principal);
                   return new OidcUserInfo(map);
               });
           }) ;
        });

        http
                .formLogin()
                ;

                ;
//        http.antMatcher("/login").authorizeHttpRequests().anyRequest().permitAll();
        return http.build();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
//                .and()
//                .oauth2ResourceServer()
//                .and()
//                .httpBasic()
        .and().csrf().disable()
        ;

        return http.build();
    }
//    @Bean
    OpaqueTokenIntrospector opaqueTokenIntrospector(){
        return new SpringOpaqueTokenIntrospector("http://localhost:9050/oauth2/introspect","clientapp","1234");
    }

//    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSourc) {
    //    JWK jwk = new RSAKey.Builder(this.key).privateKey(this.priv).build();
    //    JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
//        OAuth2AuthorizationServerConfiguration.jwtDecoder()
        return new NimbusJwtEncoder(jwkSourc);
    }
    @Bean
    RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder){
        RegisteredClient client = RegisteredClient.withId("1")
                .clientId("clientapp")
                .clientSecret(passwordEncoder.encode("1234"))
                .clientName("??????")
//               ????????????
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                ????????????
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
//                ????????????????????????????????????????????? ??????????????????IP????????????  ???????????? localhost
                .redirectUri("http://127.0.0.1:9051/login/oauth2/code/clientapp")
                .redirectUri("http://127.0.0.1:9051/authorized")
                .redirectUri("http://127.0.0.1:9051/foo/bar")
                .redirectUri("http://127.0.0.1:9051/authorize/oauth2/code/clientapp")
                .redirectUri("https://baidu.com")
//                OIDC??????
                .scope(OidcScopes.OPENID).scope("read_user_info")
//                ??????Scope
                .scope("message.read")
                .scope("message.write")
//                JWT???????????? ??????TTL  ????????????refreshToken??????
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(55))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
//                ???????????????????????????????????????????????????????????? ????????????????????????
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    /**
     * ??????JWK??????
     *
     * @return the jwk source
     */
    @SneakyThrows
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        String path = "oauthJwt.jks";
        String alias = "oauthJwt";

        ClassPathResource resource = new ClassPathResource(path);
        KeyStore jks = KeyStore.getInstance("jks");//KeyStore.getDefaultType()
        jks.load(resource.getInputStream(), "111111".toCharArray());

        RSAKey rsaKey = RSAKey.load(jks, alias, "123456".toCharArray());

        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder myJwtDecoder(JWKSource<SecurityContext> jwkSource) {
        JwtDecoder jwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        return jwtDecoder;
    }


//    @Bean
//    public EmbeddedDatabase embeddedDatabase() {
//        // @formatter:off
//        return new EmbeddedDatabaseBuilder()
//                .generateUniqueName(true)
//                .setType(EmbeddedDatabaseType.HSQL)
//                .setScriptEncoding("UTF-8")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
//                .build();
//        // @formatter:on
//    }
}
