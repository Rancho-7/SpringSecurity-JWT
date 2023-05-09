package com.lansg.SecurityJwtDemo.filter;

import com.lansg.SecurityJwtDemo.dao.UserMapper;
import com.lansg.SecurityJwtDemo.entity.User;
import com.lansg.SecurityJwtDemo.model.LoginUser;
import com.lansg.SecurityJwtDemo.util.JwtTokenUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/**
 * token过滤器 验证token有效性
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    UserMapper userMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = request.getHeader(JwtTokenUtil.TOKEN_HEADER);
        if (StringUtils.isBlank(token) || !token.startsWith(JwtTokenUtil.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }
        try {
            //如果能获取到token则Authentication进行设置，表示已认证
            SecurityContextHolder.getContext().setAuthentication(getAuthentication(token));
        } catch (Exception e) {
            e.printStackTrace();
        }
        //继续执行其他过滤器的逻辑
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) throws Exception {
        String token = tokenHeader.replace(JwtTokenUtil.TOKEN_PREFIX,"");
        //判断token是否过期
        boolean expiration = JwtTokenUtil.isExpiration(token);
        if (expiration){
            throw new Exception("过期了");
        }else{
            String username = JwtTokenUtil.getUsername(token);
            User user = userMapper.getByName(username);
            List<String> permissions = userMapper.getPermissionById(user.getId());
            LoginUser loginUser = new LoginUser(user, Collections.singleton(new SimpleGrantedAuthority(user.getRole())));
            loginUser.setPermissions(new HashSet<>(permissions));
            //新建一个UsernamePasswordAuthenticationToken用来设置Authentication
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
            return authenticationToken;
        }
    }
}
