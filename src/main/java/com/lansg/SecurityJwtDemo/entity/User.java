package com.lansg.SecurityJwtDemo.entity;

import lombok.Data;

@Data
public class User {

    private Long id;
    private String username;
    private String password;
    private String permission;
    private String role;

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", permission='" + permission + '\'' +
                ", role='" + role + '\'' +
                '}';
    }
}
