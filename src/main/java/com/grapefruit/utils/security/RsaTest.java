/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;


/**
 * RSA测试
 *
 * @author zhihuangzhang
 * @version 1.0
 * @date 2021-05-31 10:31 下午
 */
public class RsaTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, SignatureException {
        Map<String, String> map = RSAUtils.generateKeyPair();

        encryptAndDecrypt(map);

        signAndCheck(map);

        System.out.println("");
    }

    /**
     * 私钥签名，公钥验签
     */
    private static void signAndCheck(Map<String, String> map) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        String publicKey = map.get("publicKey");
        String privateKey = map.get("privateKey");

        String plainText = "Grapefruit want to try";

        String sign = RSAUtils.sign(RSAUtils.getPrivateKey(privateKey), plainText);

        String sign2 = RSAUtils.sign(RSAUtils.getPrivateKey(privateKey), "plainText");

        boolean verify = RSAUtils.verify(plainText, RSAUtils.getPublicKey(publicKey), sign2);

        System.out.println("");
    }

    /**
     * 公钥加密,私钥解密
     */
    private static void encryptAndDecrypt(Map<String, String> map) throws NoSuchPaddingException, IOException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String publicKey = map.get("publicKey");
        String privateKey = map.get("privateKey");

        String plainText = "I want to try";

        String encrypt = RSAUtils.encrypt(publicKey, plainText);

        String decrypt = RSAUtils.decrypt(encrypt, privateKey);
    }
}
