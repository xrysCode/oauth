package server.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestOperations;
import server.DT_O1.MyUser;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The type Authorization server configuration.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity(debug = true)
public class AuthorizationServerConfiguration2 extends OAuth2AuthorizationServerConfiguration {

    public static Map<String,UserDetails> cacheMap=new ConcurrentHashMap<>();

    @Bean
    UserDetailsService users(PasswordEncoder passwordEncoder) {
        MyUser myUser = new MyUser("user", passwordEncoder.encode("123"), "xxxx@163.com");
//        return new InMemoryUserDetailsManager(myUser);
        return new UserDetailsService(){

            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return myUser;
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .formLogin()
//                .loginPage("/login")
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler(){
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
                        UserDetails userDetails = (UserDetails)authentication.getPrincipal();
                        cacheMap.put(userDetails.getUsername(),userDetails);
                        System.err.println("授权-1111111111111111111111");
                        super.onAuthenticationSuccess(request, response, chain, authentication);
                    }
                })
                .and()
                .oauth2ResourceServer().opaqueToken()

                ;
//        http.antMatcher("/login").authorizeHttpRequests().anyRequest().permitAll();
        return http.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
//                .loginPage("/login1")
                .successHandler(new SavedRequestAwareAuthenticationSuccessHandler(){
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
                        UserDetails userDetails = (UserDetails)authentication.getPrincipal();
                        cacheMap.put(userDetails.getUsername(),userDetails);
                        System.err.println("登录-2222222222222222");
                        super.onAuthenticationSuccess(request, response, authentication);
                    }
                })

//                .and()
//                .httpBasic()
                .and()
                .oauth2ResourceServer()
                .opaqueToken();
        http.csrf().disable()
        ;

        return http.build();
    }
    @Bean
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
                .clientName("测试")
//               授权方法
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                授权类型
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
//                回调地址名单，不在此列将被拒绝 而且只能使用IP或者域名  不能使用 localhost
                .redirectUri("http://127.0.0.1:9051/login/oauth2/code/clientapp")
                .redirectUri("http://127.0.0.1:9051/authorized")
                .redirectUri("http://127.0.0.1:9051/foo/bar")
                .redirectUri("http://127.0.0.1:9051/authorize/oauth2/code/clientapp")
                .redirectUri("https://baidu.com")
//                OIDC支持
                .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope("read_user_info")
//                其它Scope
                .scope("message.read")
                .scope("message.write")
//                JWT的配置项 包括TTL  是否复用refreshToken等等
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(55))
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
//                配置客户端相关的配置项，包括验证密钥或者 是否需要授权页面
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    /**
     * 加载JWK资源
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


//    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkSetUri="http://localhost:9050/oauth2/jwks";
    @Bean
    JwtDecoder myJwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
        JwtDecoder jwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        return jwtDecoder;
    }

}
