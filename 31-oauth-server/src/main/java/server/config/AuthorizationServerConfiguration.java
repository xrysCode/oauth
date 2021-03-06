package server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
//import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyStore;
import java.util.UUID;

/**
 * The type Authorization server configuration.
 */
//@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    /**
     * ?????? OAuth2.0 provider?????????
     *
     * @return the provider settings
     */
//    @Bean
    public ProviderSettings providerSettings(@Value("${server.port}") Integer port) {
        //TODO ????????????????????????
        return ProviderSettings.builder().issuer("http://localhost:" + port).build();
    }
    /**
     * Authorization server ??????
     *
     * @param http the http
     * @return the security filter chain
     * @throws Exception the exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Authorization Server ????????????
        this.defaultOAuth2AuthorizationServerConfigurer(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    void defaultOAuth2AuthorizationServerConfigurer(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        // TODO ????????????????????????authorizationServerConfigurer???????????????????????????
        RequestMatcher authorizationServerEndpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // ?????? ????????????????????????????????????
        http.requestMatcher(authorizationServerEndpointsMatcher)
                .authorizeRequests().anyRequest().authenticated().and()
                // ????????????????????????csrf
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerEndpointsMatcher))
                // ??????form??????
                .formLogin()
                .and()
                // ?????? ????????????????????????
                .apply(authorizationServerConfigurer);
    }


    /**
     * ???jwt token ????????????????????????????????????
     *
     * @return oauth 2 token customizer
     */
//    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return jwtEncodingContext -> {
            JwtClaimsSet.Builder claims = jwtEncodingContext.getClaims();
            claims.claim("xxxx", "xxxxx");
            JwtEncodingContext.with(jwtEncodingContext.getHeaders(), claims);
        };
    }


    /**
     * ???????????????????????????
     *
     * @param jdbcTemplate the jdbc template
     * @return the registered server repository
     */
    @SneakyThrows
//    @Bean
    public RegisteredClientRepository registeredClientRepository() {//JdbcTemplate jdbcTemplate
        // TODO ????????? ????????????????????????????????? ??????????????????????????????
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//               ?????????ID?????????
                .clientId("felord-server")
                .clientSecret("secret")
//                ?????? ????????????
                .clientName("felord")
//                ????????????
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                ????????????
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                ????????????????????????????????????????????? ??????????????????IP????????????  ???????????? localhost
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/felord-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .redirectUri("http://127.0.0.1:8080/foo/bar")
                .redirectUri("https://baidu.com")
//                OIDC??????
                .scope(OidcScopes.OPENID)
//                ??????Scope
                .scope("message.read")
                .scope("message.write")
//                JWT???????????? ??????TTL  ????????????refreshToken??????
                .tokenSettings(TokenSettings.builder().build())
//                ???????????????????????????????????????????????????????????? ????????????????????????
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

//         ?????????????????????  ???????????? ????????????JdbcRegisteredClientRepository
//        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
////TODO        return registeredClientRepository;
//        registeredClientRepository.save(registeredClient);
//        return registeredClientRepository;
        return null;
    }

    /**
     * ????????????
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered server repository
     * @return the o auth 2 authorization service
     */
//    @Bean
//    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
//        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
//    }

    /**
     * Authorization consent service o auth 2 authorization consent service.
     *
     * @param jdbcTemplate               the jdbc template
     * @param registeredClientRepository the registered server repository
     * @return the o auth 2 authorization consent service
     */
//    @Bean
//    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
//        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
//    }

    /**
     * ??????JWK??????
     *
     * @return the jwk source
     */
    @SneakyThrows
//    @Bean
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




    /**
     * OAuth2.0 ????????????????????????????????????????????????????????????H2???????????????????????????
     *
     * @return the embedded database
     */
//    @Bean
//    public EmbeddedDatabase embeddedDatabase() {
//        // @formatter:off
//        return new EmbeddedDatabaseBuilder()
//                .generateUniqueName(true)
//                .setType(EmbeddedDatabaseType.H2)
//                .setScriptEncoding("UTF-8")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
//                .addScript("org/springframework/security/oauth2/server/authorization/server/oauth2-registered-server-schema.sql")
//                .build();
//        // @formatter:on
//    }

}
