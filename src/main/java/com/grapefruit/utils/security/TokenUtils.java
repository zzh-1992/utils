/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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

    //token密钥
    public static final String TOKEN_SECRET = "d621d333dec745fd8d44ad38428714de";

    /**
     * 生成token密钥
     *
     * @return token字符串
     */
    public static String createUUID() {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        System.out.println(uuid);
        return uuid;
    }

    /**
     * 生成token(HMAC256)
     *
     * @param userName   用户名
     * @param password   密码
     * @param expireTime token过期时间
     * @return token字符串
     */
    public static String generateTokenWithHMAC256(String userName, String password, Long expireTime) {
        //设置过期时间
        Date date = new Date(System.currentTimeMillis() + expireTime);

        //设置算法
        Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);

        //设置参数
        Map<String, Object> header = new HashMap<>(2);
        header.put("typ", "JWT");
        header.put("alg", "HS256");

        //生成token
        String token = JWT.create()
                .withHeader(header)
                .withClaim("userName", userName)
                .withClaim("password", password)
                .withExpiresAt(date)
                .sign(algorithm);
        System.out.println("生成的token:" + token);
        return token;
    }

    /**
     * 生成token(HMAC256)
     *
     * @param userName   用户名
     * @param password   密码
     * @param expireTime token过期时间
     * @return token字符串
     */
    public static String generateTokenWithRSA512(String userName, String password, Long expireTime) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        //设置过期时间
        Date date = new Date(System.currentTimeMillis() + expireTime);

        //获取存有公钥对象、密钥对象的map集合
        Map<String, Object> keyMap = RSAUtils.getKey();

        //设置算法
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) keyMap.get("publicKey"), (RSAPrivateKey) keyMap.get("privateKey"));

        //设置参数
        Map<String, Object> header = new HashMap<>(2);
        header.put("typ", "JWT");
        header.put("alg", "RSA512");

        //生成token
        String token = JWT.create()
                .withHeader(header)
                .withClaim("userName", userName)
                .withClaim("password", password)
                .withExpiresAt(date)
                .sign(algorithm);
        System.out.println("生成的token:" + token);
        return token;
    }

    /**
     * 校验token(HMAC256)
     *
     * @param token
     * @return 返回token的校验结果(true token有效, false token 无效)
     */
    public static boolean checkTokenWithHMAC256(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            //e.printStackTrace();
            return false;
        }
    }

    /**
     * 校验token(RSA512)
     *
     * @param token
     * @return 返回token的校验结果(true token有效, false token 无效)
     */
    public static boolean checkTokenWithRSA512(String token) {
        try {
            Map<String, Object> keyMap = RSAUtils.getKey();

            //获取存有公钥对象、密钥对象的map集合
            Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) keyMap.get("publicKey"), (RSAPrivateKey) keyMap.get("privateKey"));

            JWTVerifier verifier = JWT.require(algorithm).build();
            verifier.verify(token);
            return true;
        } catch (Exception e) {
            //e.printStackTrace();
            return false;
        }
    }

    /**
     * 解析token的原有信息
     *
     * @param token
     * @return 原有信息
     */
    public static String getContentFromToken(String token) {
        DecodedJWT decode = JWT.decode(token);
        String userName = decode.getClaim("userName").asString();
        String password = decode.getClaim("password").asString();
        System.out.println("解析的用户名:" + userName);
        System.out.println("解析的密码:" + password);
        return "";
    }
}
