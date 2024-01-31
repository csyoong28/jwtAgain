package com.example.jwtagain;


import com.google.common.base.Throwables;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;



import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtHelper {
    /**
     * 生成用户token
     *
     * @param jwtInfo    待加密的用户信息
     * @param privateKey base64加密私钥
     * @param expire     jwt过期时间
     * @return token
     */
    public static Map<String, Object> generateUserToken(JwtUserInfo jwtInfo, String privateKey, int expire) {
        JwtBuilder jwtBuilder = Jwts.builder()
                //设置主题
                .setSubject(String.valueOf(jwtInfo.getUserId()))
                .claim(JwtConstants.JWT_KEY_ORG_ID, jwtInfo.getOrgId());
        return generateToken(jwtBuilder, privateKey, expire);
    }

    /**
     * 生成token
     *
     * @param builder    JwtBuilder
     * @param privateKey base64加密私钥
     * @param expire     jwt过期时间
     * @return token
     */
    protected static Map<String, Object> generateToken(JwtBuilder builder, String privateKey, int expire) {
        try {
            //返回的字符串便是我们的jwt串了
            String compactJws = builder
                    .setExpiration(CommonUtils.localDateTime2Date(LocalDateTime.now().plusSeconds(expire)))
                    //设置算法（必须）
                    .signWith(SignatureAlgorithm.RS256, getRSAPrivateKey(privateKey))
                    //这个是全部设置完成后拼成jwt串的方法
                    .compact();
            Map<String, Object> map = new HashMap<>();
            map.put("expire", expire);
            map.put("token", compactJws);
            return map;
            //return new Token(expire, compactJws);
        } catch (Exception e) {
            log.error("generate token fail, privateKey:[{}], err:[{}]", privateKey, Throwables.getStackTraceAsString(e));
            // 抛出自定义异常
        }
        return null;
    }

    /**
     * 获取token中的用户信息
     *
     * @param token     token
     * @param publicKey base64加密公钥
     * @return /
     */
    public static JwtUserInfo getJwtFromToken(String token, String publicKey) {
        Jws<Claims> claimsJws = parserToken(token, publicKey);
        if (claimsJws != null) {
            Claims body = claimsJws.getBody();
            String strUserId = body.getSubject();
            String strOrgId = body.get(JwtConstants.JWT_KEY_ORG_ID) + "";
            return JwtUserInfo.builder()
                    .userId(CommonUtils.intValueOf0(strUserId))
                    .orgId(CommonUtils.intValueOf0(strOrgId))
                    .build();
        }
        return null;
    }

    /**
     * 公钥解析token
     *
     * @param token     token
     * @param publicKey base64加密公钥
     * @return /
     */
    private static Jws<Claims> parserToken(String token, String publicKey) {
        try {
            return Jwts.parser().setSigningKey(getRSAPublicKey(publicKey)).parseClaimsJws(token);
        } catch (ExpiredJwtException ex) {
            //过期
            // 抛出自定义异常
        } catch (SignatureException ex) {
            //签名错误
            // 抛出自定义异常
        } catch (IllegalArgumentException ex) {
            //token 为空
            // 抛出自定义异常
        } catch (Exception e) {
            log.error("parse token fail, token:[{}], publicKey:[{}], err:[{}]", token, publicKey, Throwables.getStackTraceAsString(e));
            // 抛出自定义异常
        }
        return null;
    }

    /**
     * 获取 RSAPublicKey
     *
     * @param pubKey base64加密公钥
     */
    private static RSAPublicKey getRSAPublicKey(String pubKey) throws NoSuchAlgorithmException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKey));
        RSAPublicKey publicKey = null;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try {
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            log.error("get RSAPublicKey fail ,pubKey:[{}] ,err:[{}]", pubKey, Throwables.getStackTraceAsString(e));
        }
        return publicKey;
    }

    /**
     * 获取 RSAPrivateKey
     *
     * @param priKey base64加密私钥
     */
    private static RSAPrivateKey getRSAPrivateKey(String priKey) throws NoSuchAlgorithmException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKey));
        RSAPrivateKey privateKey = null;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        try {
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            log.error("get RSAPrivateKey fail ,priKey:[{}], err:[{}]", priKey, Throwables.getStackTraceAsString(e));
        }
        return privateKey;
    }
    /**
     * 生成base64加密后的公钥和私钥
     */
    public static Map<String, String> genRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        HashMap<String, String> keyMap = new HashMap<>();
        keyMap.put("publicKey", Base64.encodeBase64String(publicKeyBytes));
        keyMap.put("privateKey", Base64.encodeBase64String(privateKeyBytes));
        return keyMap;
    }
}