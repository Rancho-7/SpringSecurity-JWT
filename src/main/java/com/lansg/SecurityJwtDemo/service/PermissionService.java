package com.lansg.SecurityJwtDemo.service;

import com.lansg.SecurityJwtDemo.model.LoginUser;
import com.lansg.SecurityJwtDemo.util.SecurityUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

/**
 * 自定义权限实现，ss取自SpringSecurity首字母
 */
@Service("ss")
public class PermissionService {
    public boolean hasPer(String permission) throws Exception {
        if (StringUtils.isBlank(permission)){
            return false;
        }
        LoginUser loginUser = SecurityUtil.getLoginUser();
        if (loginUser == null || CollectionUtils.isEmpty(loginUser.getPermissions())) {
            return false;
        }
        return loginUser.getPermissions().contains(StringUtils.trim(permission));
    }
}
