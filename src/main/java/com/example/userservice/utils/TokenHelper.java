package com.example.userservice.utils;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class TokenHelper {

    @Value("${access.token.secret}")
    private String secretKeyForAccessToken;

    @Value("${refresh.token.secret}")
    private String secretKeyForRefreshToken;

    @Value("${access.token.expires.seconds}")
    private long accessTokenExpiresSeconds;

    @Value("${refresh.token.expires.seconds}")
    private long refreshTokenExpiresSeconds;

    public Algorithm getAccessAlgorithm(){
        return Algorithm.HMAC256(secretKeyForAccessToken.getBytes());
    }

    public Algorithm getRefreshAlgorithm(){
        return Algorithm.HMAC256(secretKeyForRefreshToken.getBytes());
    }

    public long getAccessTokenExpiresSeconds(){
        return accessTokenExpiresSeconds * 1000;
    }

    public long getRefreshTokenExpiresSeconds(){
        return refreshTokenExpiresSeconds * 1000;
    }



}
