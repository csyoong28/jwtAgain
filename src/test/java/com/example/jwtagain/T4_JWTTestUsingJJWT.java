package com.example.jwtagain;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;


@SpringBootTest
public class T4_JWTTestUsingJJWT {
    String tokenForTest;  //from setUp(), used in testResolveToken()
    @BeforeEach
    public void setUp() {
        // Set up common test data or actions here
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 60);
        String token = JWT.create()
                .withHeader(new HashMap<>())  // Header
                .withClaim("userId", 21)  // Payload
                .withClaim("userName", "baobao")
                .withExpiresAt(calendar.getTime())  // 过期时间
                .sign(Algorithm.HMAC256("!34ADAS"));  // 签名用的secret
        tokenForTest = token;
    }

    @Test
    // using own jwt util
    public void testUsingJjwtUtils(){
        String token = JWTUtilsWithJjwt.getJwtToken("21", "baobao");
        boolean b = JWTUtilsWithJjwt.checkToken(token);
        Jws<Claims> decode = JWTUtilsWithJjwt.decode(token);
        String userId = decode.getBody().get("id").toString();
        String userName = decode.getBody().get("nickname").toString();
        System.out.println(userId);
        System.out.println(userName);
    }

}
