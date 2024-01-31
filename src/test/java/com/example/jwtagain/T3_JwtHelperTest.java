package com.example.jwtagain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;


@SpringBootTest
public class T3_JwtHelperTest {
    /**
     * 私钥
     */
    @Value("${authentication.jwt.priKey}")
    private String priKey;
    /**
     * 公钥
     */
    @Value("${authentication.jwt.pubKey}")
    private String pubKey;
    /**
     * 工期时间 s
     */
    @Value("${authentication.jwt.expire}")
    private Integer expire;

    //same as T2_JWTTestRsa
    @Test
    public void testJwtWithRsa() {
        Map<String, Object> map = JwtHelper.generateUserToken(JwtUserInfo.builder().userId(20000).orgId(200).build(), priKey, expire);
        JwtUserInfo userInfo = JwtHelper.getJwtFromToken(map.get("token").toString(), pubKey);
        System.out.println(userInfo);
    }


}
