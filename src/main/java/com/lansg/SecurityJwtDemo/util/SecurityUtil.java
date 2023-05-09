package com.lansg.SecurityJwtDemo.util;

import com.lansg.SecurityJwtDemo.model.LoginUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtil {

    public static LoginUser getLoginUser() throws Exception {
        try{
            return (LoginUser) getAuthentication().getPrincipal();
        }catch (Exception e){
            throw new Exception("获取用户信息异常");
        }
    }

    /**
     * 获取Authentication
     */
    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

}
