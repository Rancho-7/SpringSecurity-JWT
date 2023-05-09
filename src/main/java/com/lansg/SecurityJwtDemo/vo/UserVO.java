package com.lansg.SecurityJwtDemo.vo;

import lombok.Data;

@Data
public class UserVO {
    private String username;
    private String password;
    private Integer rememberMe;
}
