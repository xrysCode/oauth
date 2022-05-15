package server.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

@Data
public class MyUser implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        GrantedAuthority grantedAuthority=()->"GrantedAuthority";
//        return Collections.singletonList(grantedAuthority);
        return  Collections.singletonList(new SimpleGrantedAuthority("grantedAuthority"));
    }
    String password;
    String username;
    String email;

    public MyUser(String username, String password, String email) {
        this.password = password;
        this.username = username;
        this.email = email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
