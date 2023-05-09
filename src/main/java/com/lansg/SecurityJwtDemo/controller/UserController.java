package com.lansg.SecurityJwtDemo.controller;

import com.lansg.SecurityJwtDemo.dao.UserMapper;
import com.lansg.SecurityJwtDemo.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/")
public class UserController {

    @Autowired
    UserMapper userMapper;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public String register(@RequestBody Map<String,String> registerUser){
        User user = new User();
        user.setUsername(registerUser.get("username"));
        //对密码进行一下加密
        user.setPassword(bCryptPasswordEncoder.encode(registerUser.get("password")));
        user.setPermission(registerUser.get("permission"));
        user.setRole(registerUser.get("role"));
        userMapper.insertUser(user);
        return user.toString();
    }
}
