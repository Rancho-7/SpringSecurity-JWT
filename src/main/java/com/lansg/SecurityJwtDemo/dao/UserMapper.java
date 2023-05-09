package com.lansg.SecurityJwtDemo.dao;

import com.lansg.SecurityJwtDemo.entity.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {

    //根据用户名获取用户
    User getByName(String username);

    //根据用户id获取用户权限
    List<String> getPermissionById(Long id);

    //新增一个用户
    int insertUser(User user);
}
