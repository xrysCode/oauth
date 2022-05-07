package oauth2.server1.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//@Configuration
public class MyAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {
    /**
     * @param loginFormUrl URL where the login page can be found. Should either be
     *                     relative to the web-app context path (include a leading {@code /}) or an absolute
     *                     URL.
     */
    public MyAuthenticationEntryPoint(@Value("${loginFormUrl:/login}") String loginFormUrl) {
        super(loginFormUrl);
    }

    public String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationException exception) {
        System.out.println("---------------");
        return getLoginFormUrl();
    }

//    @Override
//    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//
//    }

    @Bean
    public ExceptionTranslationFilter exceptionTranslationFilter(){
        return new ExceptionTranslationFilter(new MyAuthenticationEntryPoint("/login"));
    }
}
