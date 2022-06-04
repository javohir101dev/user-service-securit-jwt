package com.example.userservice.jwt;

import com.auth0.jwt.JWT;
import com.example.userservice.utils.TokenHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.stream.Collectors;

@Component("JwtProvider")
@RequiredArgsConstructor
public class JwtProvider {

    private final TokenHelper tokenHelper;

    public String accessToken(HttpServletRequest request, User user){
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + tokenHelper.getAccessTokenExpiresSeconds()))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(tokenHelper.getAccessAlgorithm());
        return accessToken;
    }

    public String refreshToken(HttpServletRequest request, User user){
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + tokenHelper.getRefreshTokenExpiresSeconds()))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(tokenHelper.getRefreshAlgorithm());
        return refreshToken;
    }
}
