/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.grapefruit.utils.string.LocalStringUtils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * token工具类(生成token和校验token)
 *
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2020/9/13 22:59:48
 */
public class TokenUtils {

    //过期时间
    //public static final long EXPIRE_Time = 30 * 60 * 1000;
    //public static final long EXPIRE_Time = 3000;

    /**
     * user name or account
     */
    public static final String USER_NAME = "userName";

    /**
     * the id to find token in redis
     */
    public static final String UUID = "uuid";

    /**
     * user password
     */
    public static final String PASSWORD = "password";

    /**
     * token密钥
     */
    public static final String TOKEN_SECRET = "d621d333dec745fd8d44ad38428714de";

    /**
     * 生成token(HMAC256)
     *
     * @param userName   用户名
     * @param password   密码
     * @param expireTime token过期时间
     * @return token字符串
     */
    public static String generateTokenWithHMAC256(String userName, String password, Long expireTime) {
        //设置算法
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);

        //设置参数
        Map<String, Object> header = new HashMap<>(2);
        header.put("typ", "JWT");
        header.put("alg", "HS256");

        return createToken(header, algorithm, userName, password, expireTime);
    }

    /**
     * 生成token(HMAC256)
     *
     * @param userName   用户名
     * @param password   密码
     * @param expireTime token过期时间
     * @return token字符串
     */
    public static String generateTokenWithRSA512(String userName, String password, Long expireTime) throws
            NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        //获取存有公钥对象、密钥对象的map集合
        Map<String, Object> keyMap = RSAUtils.getKey();

        //设置算法
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) keyMap.get("publicKey"), (RSAPrivateKey) keyMap.get(
                "privateKey"));

        //设置参数
        Map<String, Object> header = new HashMap<>(2);
        header.put("typ", "JWT");
        header.put("alg", "RSA512");

        return createToken(header, algorithm, userName, password, expireTime);
    }

    /**
     * createToken
     *
     * @param header     header
     * @param algorithm  加密算法
     * @param userName   用户名称
     * @param password   密码
     * @param expireTime 过期时间
     * @return token
     */
    public static String createToken(Map<String, Object> header, Algorithm algorithm, String userName,
                                     String password, Long expireTime) {
        //设置过期时间
        Date date = new Date(System.currentTimeMillis() + expireTime);

        //生成token
        String token = JWT.create()
                .withHeader(header)
                .withClaim(USER_NAME, userName)
                .withClaim(PASSWORD, password)
                .withClaim(UUID, LocalStringUtils.getUUID())
                .withExpiresAt(date)
                .sign(algorithm);
        System.out.println("生成的token:" + token);
        return token;
    }

    /**
     * 校验token(HMAC256)
     *
     * @param token token
     * @return 返回token的校验结果(true token有效, false token 无效)
     */
    public static boolean checkTokenWithHMAC256(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            //TODO handle error
            return false;
        }
    }

    /**
     * 校验token(RSA512)
     *
     * @param token token
     * @return 返回token的校验结果(true token有效, false token 无效)
     */
    public static boolean checkTokenWithRSA512(String token) {
        try {
            Map<String, Object> keyMap = RSAUtils.getKey();

            //获取存有公钥对象、密钥对象的map集合
            Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) keyMap.get("publicKey"),
                    (RSAPrivateKey) keyMap.get("privateKey"));

            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            //TODO handle error
            return false;
        }
    }

    /**
     * 解析token的原有信息
     *
     * @param token token
     * @return 原有信息
     */
    public static String getContentFromToken(String token) {
        DecodedJWT decode = JWT.decode(token);
        String userName = decode.getClaim(USER_NAME).asString();
        String password = decode.getClaim(PASSWORD).asString();

        Date expiresAt = decode.getExpiresAt();
        System.out.println("解析的用户名:" + userName);
        System.out.println("解析的密码:" + password);
        System.out.println("过期时刻:" + expiresAt);
        return "";
    }

    /**
     * 解析token的过期时间
     *
     * @param token token
     * @return 过期时刻
     */
    public static Date getExpiresFromToken(String token) {
        return JWT.decode(token).getExpiresAt();
    }

    /**
     * 解析token的原有信息
     *
     * @param token token
     * @return 原有信息
     */
    public static Map<String, Claim> getClaimsFromToken(String token) {
        DecodedJWT decode = JWT.decode(token);
        return decode.getClaims();
    }
}
