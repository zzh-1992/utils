/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import com.alibaba.fastjson.JSON;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * AES/GCM
 *
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2021/05/21 21:36:07
 */
public class AesGcm {

    private static final String AES = "AES";
    private static final String KEY = "key";
    private static final String IV = "iv";

    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Map<String, byte[]> map = getSecret();

        aesgcm();

        Req req = new Req("grapefruit1999", "001", 2021);
        String jsonString = JSON.toJSONString(req);

        // 加密明文获得
        byte[] cipherBytes = encrypt(jsonString, map);

        // 将16进制字节转换为16进制字符串(生成签名)
        String digest = Hex.toHexString(cipherBytes);

        // 将16进制字符串解码为16进制字节
        byte[] cipherBytes2 = Hex.decode(digest);

        // 解密获得原文
        String decrypt = decrypt(cipherBytes2, map);
        System.out.println();
    }

    // 获取密钥
    public static Map<String, byte[]> getSecret() {
        // 使用强随机数
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);

        byte[] iv = new byte[12]; // 使用同一密钥时初始向量绝不能重用
        secureRandom.nextBytes(iv);

        Map<String, byte[]> map = new HashMap<>();
        map.put(KEY, key);
        map.put(IV, iv);
        return map;
    }


    /**
     * 加密操作
     *
     * @param plainText 明文
     * @param map       密钥参数
     * @return 秘文byte
     * @throws NoSuchPaddingException             NoSuchPaddingException
     * @throws NoSuchAlgorithmException           NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException InvalidAlgorithmParameterException
     * @throws InvalidKeyException                InvalidKeyException
     * @throws IllegalBlockSizeException          IllegalBlockSizeException
     * @throws BadPaddingException                BadPaddingException
     */
    public static byte[] encrypt(String plainText, Map<String, byte[]> map) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 对输入数据进行编码，生成十六进制编码的字节数组。
        byte[] plainTextBytes = Hex.encode(plainText.getBytes());

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, map.get(IV)); // 256 位长的认证标签
        SecretKey secretKey = new SecretKeySpec(map.get(KEY), AES);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // 执行加密操作
        return cipher.doFinal(plainTextBytes);
    }

    /**
     * 解密操作
     *
     * @param cipherBytes 密钥byte[]
     * @param map         密钥参数
     * @return 明文
     * @throws NoSuchPaddingException             NoSuchPaddingException
     * @throws NoSuchAlgorithmException           NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException InvalidAlgorithmParameterException
     * @throws InvalidKeyException                InvalidKeyException
     * @throws IllegalBlockSizeException          IllegalBlockSizeException
     * @throws BadPaddingException                BadPaddingException
     */
    public static String decrypt(byte[] cipherBytes, Map<String, byte[]> map) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(map.get(KEY), AES), new GCMParameterSpec(128, map.get(IV)));
        byte[] doFinalBytes = cipher.doFinal(cipherBytes);
        return new String(Hex.decode(doFinalBytes));
    }


    public static void aesgcm() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, AES);

        byte[] iv = new byte[12]; // 使用同一密钥时初始向量绝不能重用
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); // 256 位长的认证标签
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        Req req = new Req("grapefruit", "001", 2021);
        String jsonString = JSON.toJSONString(req);
        // 明文字符串转明文byte
        byte[] jsonStringBytes = jsonString.getBytes();

        // 明文byte==>16进制byte
        byte[] plainTextBytes = Hex.encode(jsonStringBytes);

        // 执行加密操作
        byte[] cipherText = cipher.doFinal(plainTextBytes);

        /*ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();*/

        // 解密
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, AES), new GCMParameterSpec(128, iv));

        // 16进制字节
        byte[] plainText2 = cipher2.doFinal(cipherText);

        // 16进制byte转明文字符串
        String plainText = new String(Hex.decode(plainText2));

        System.out.println(plainText);
    }

    @Data
    @AllArgsConstructor
    public static class Req {
        String name;
        String id;
        int age;
    }
}
