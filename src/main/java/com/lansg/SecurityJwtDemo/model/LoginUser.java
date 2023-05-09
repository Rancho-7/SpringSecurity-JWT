package com.lansg.SecurityJwtDemo.model;

import com.lansg.SecurityJwtDemo.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
public class LoginUser implements UserDetails {

    private Long id;
    private String username;
    private String password;
    //通过自定义方式进行授权
    private Set<String> permissions = new HashSet<String>();

    //通过springSecurity进行授权
    private Collection<? extends GrantedAuthority> authorities;

    public LoginUser(){}

    public LoginUser(User user,Collection<? extends GrantedAuthority> authorities) {
        id = user.getId();
        username = user.getUsername();
        password = user.getPassword();
        permissions.add(user.getPermission());
        this.authorities = authorities;

    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
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
