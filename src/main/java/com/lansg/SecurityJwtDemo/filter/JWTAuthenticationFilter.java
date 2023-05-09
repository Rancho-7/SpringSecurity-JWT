package com.lansg.SecurityJwtDemo.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lansg.SecurityJwtDemo.model.LoginUser;
import com.lansg.SecurityJwtDemo.util.JwtTokenUtil;
import com.lansg.SecurityJwtDemo.vo.UserVO;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ThreadLocal<Integer> rememberMe = new ThreadLocal<>();
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        // 从输入流中获取到登录的信息
        try {
            UserVO vo = new ObjectMapper().readValue(request.getInputStream(), UserVO.class);
            rememberMe.set(vo.getRememberMe() == null ? 0 : vo.getRememberMe());
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(vo.getUsername(), vo.getPassword(), new ArrayList<>())
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 成功验证后调用的方法
    // 如果验证成功，就生成token并返回
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        LoginUser loginUser = (LoginUser) authResult.getPrincipal();
        System.out.println("loginUser:" + loginUser.toString());
        boolean isRemember = rememberMe.get() == 1;

        String role = "";
        String token = JwtTokenUtil.createToken(loginUser.getUsername(), role, isRemember);
        /* 返回创建成功的token
         但是这里创建的token只是单纯的token
         按照jwt的规定，最后请求的时候应该是 `Bearer token`*/
        response.setHeader("token", JwtTokenUtil.TOKEN_PREFIX + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.getWriter().write("authentication failed, reason: " + failed.getMessage());
    }
}
