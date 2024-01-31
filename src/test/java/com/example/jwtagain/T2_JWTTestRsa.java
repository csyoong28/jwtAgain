package com.example.jwtagain;

import cn.hutool.crypto.asymmetric.RSA;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

// able to use RSA, but the public private key is from other example, not i generate myself.
//still need to know how to generate one pair
@SpringBootTest
public class T2_JWTTestRsa {
    String tokenForTest;  //from setUp(), used in testResolveToken()
    String privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAL88LLsnwb2mo27p/3CSsnrKxhUBLQpCEMmpP5mvBQ72M6uTglU3OF06r5XVH0qP6CduSGJhg94/VDEBKrD2g3jUSJSf52ue6C+CTxBRwa/QQIGv7Un3K3M5lGqUNcDAAjTlmGxCmS1Gw5PkGI387Pu/91yWzBgGTTVzj6G21uA7AgMBAAECgYEAroVbCR3aOJq38gPIo1KtYVRme0rMcN0j9vXnXfiUtDfJpd6DhgNUA/kHvsR1vxUft8R0eJwnvQ6sZeB7tm3yQiEK67r3fKAIsPQHZRwSOcu/DyXtNoYFzhyq49lsuqC6Hfl0UYDietVTdUTmdIbSD35cwH/E8nGDlWn9njyhGokCQQDtzZSy01iFcu2TTI+ImcDkhgfZDCjxHAF3hpyK/8IGdzLTqhLQb13XJKQ5F/zQTOheoZ8s+6FXfK9TgtBdX75HAkEAzd5a1fAvpHnugw4W154fDG0bF0QsTAUyX5lAEN7DLxgAj5lj2tEIsb7u4P2f7EtVSDVj2atV31lCF35eYThEbQJBAJMWDVtujdo88+Wf/Ueokj7HCCOf+dLoV5/uivUOrJwDLlTtZSW3PHvOFiWaSK0uZKvjm+je2zSZ0nf8+ZRHnBECQQC3xEWndWjB1EnxWLFRNYeXqwkkwqkcDwOBTKZgqMjoj+9oP89f83pkWACafCu2XSS6eVYxZn0YC3Aw0o/jDrwdAkAuBjjg3kw7jOueJAe4nm9tJZiDNwaTtGBiva38KyfeD8NDxTee8mmHmZv5EXbqs0SRgOMk2lHURIRNdQ2cF2fs";
    String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/PCy7J8G9pqNu6f9wkrJ6ysYVAS0KQhDJqT+ZrwUO9jOrk4JVNzhdOq+V1R9Kj+gnbkhiYYPeP1QxASqw9oN41EiUn+drnugvgk8QUcGv0ECBr+1J9ytzOZRqlDXAwAI05ZhsQpktRsOT5BiN/Oz7v/dclswYBk01c4+httbgOwIDAQAB";

    @BeforeEach
    public void setUp() {
        // Set up common test data or actions here
        // 指定token过期时间为10秒
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 60);
        // 利用hutool创建RSA
        RSA rsa = new RSA(privateKey, null);
        // 获取私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) rsa.getPrivateKey();
        String token = JWT.create()
                .withHeader(new HashMap<>())  // Header
                .withClaim("userId", 21)  // Payload
                .withClaim("userName", "baobao")
                .withExpiresAt(calendar.getTime())  // 过期时间
                .sign(Algorithm.RSA256(null, privateKey));  // 签名用的secret
        tokenForTest = token;
    }

    @Test
    @Order(1)
    // can create jwt token, with custom claims
    public void testGenerateTokenWithRsa(){
        // 指定token过期时间为10秒
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 60);
        // 利用hutool创建RSA
        RSA rsa = new RSA(privateKey, null);
        // 获取私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) rsa.getPrivateKey();
        String token = JWT.create()
                .withHeader(new HashMap<>())  // Header
                .withClaim("userId", 21)  // Payload
                .withClaim("userName", "baobao")
                .withExpiresAt(calendar.getTime())  // 过期时间
                .sign(Algorithm.RSA256(null, privateKey));  // 签名用的secret
        tokenForTest = token;
        System.out.println(token);
    }

    @Test
    @Order(2)
    // can get jwt token's claim
    public void testResolveTokenWithRsa(){
        RSA rsa = new RSA(null, publicKey);
        // 获取RSA公钥
        RSAPublicKey publicKey = (RSAPublicKey) rsa.getPublicKey();
        // 创建解析对象，使用的算法和secret要与创建token时保持一致
        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256(publicKey, null)).build();
        // 解析指定的token
        DecodedJWT decodedJWT = jwtVerifier.verify(this.tokenForTest);
        // 获取解析后的token中的payload信息
        Claim userId = decodedJWT.getClaim("userId");
        Claim userName = decodedJWT.getClaim("userName");
        System.out.println(userId.asInt());
        System.out.println(userName.asString());
        // 输出超时时间
        System.out.println(decodedJWT.getExpiresAt());
    }

}
