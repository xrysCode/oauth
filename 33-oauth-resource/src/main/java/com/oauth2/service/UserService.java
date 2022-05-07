package com.oauth2.service;

import com.oauth2.resource.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * @Author xry
 * @Date 2022/4/21 15:19
 */
@Service
public class UserService implements UserDetailsService {
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//				return User.builder().username("user").password("$2a$10$X5SDPDiUVFiay9eYxpOVoeK.BYfaaL.Shg3jDcpCKuSy74B2mzUoe")
//						.roles("user")
//						.build();

        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = requestAttributes.getRequest();
        Object attribute = request.getParameter("username");
        System.out.println(attribute);

        return new UserInfo("user","xxx@em.com",bCryptPasswordEncoder.encode("123"));
    }

}
