package com.lansg.SecurityJwtDemo.service;

import com.lansg.SecurityJwtDemo.dao.UserMapper;
import com.lansg.SecurityJwtDemo.model.LoginUser;
import com.lansg.SecurityJwtDemo.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.getByName(username);
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        return new LoginUser(user,authorities);
    }
}
