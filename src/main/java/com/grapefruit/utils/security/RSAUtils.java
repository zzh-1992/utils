/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 基于RSA算法的加密、解密、签名、验签
 *
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2020/9/12 19:23:16
 */
public class RSAUtils {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        generateKeyPair();
    }

    //网友博客地址:https://www.cnblogs.com/longyao/p/11346984.html

    //使用密钥字符串生成生成密钥对象
    public static PrivateKey getPrivateKey(String basicPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //生成钥匙工厂
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        //生成密钥的解码字节数组
        //byte[] decodedKey  = Base64.decodeBase64(basicPrivateKey);
        byte[] decodedKey = Base64.getDecoder().decode(basicPrivateKey);

        //私钥编码
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodedKey);

        //生成密钥
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    //使用公钥字符串生成生成公钥对象
    public static PublicKey getPublicKey(String basicPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //生成钥匙工厂
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        //生成密钥的解码字节数组
        //byte[] decodedKey  = Base64.decodeBase64(basicPublicKey);
        byte[] decodedKey = Base64.getDecoder().decode(basicPublicKey);

        //公钥编码
        //PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodedKey);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodedKey);

        //生成公钥
        //PublicKey publicKey = keyFactory.generatePublic(pkcs8EncodedKeySpec);  X509EncodedKeySpec
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    /**
     * 从系统路径获取密钥对象,公钥对象的map集合
     *
     * @return map
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public static Map<String, Object> getKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Map<String, Object> map = new HashMap(2);

        //调用IO工具获取私钥字符串,并生成私钥对象
        PrivateKey privateKey = getPrivateKey(IO.readPrivateKeyStr());

        /*RSAPrivateKey privateKey = (RSAPrivateKey)KeyFactory.
                getInstance("RSA").
                generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(IO.readPrivateKeyStr())));*/

        //调用IO工具获取公钥钥字符串,并生成公钥对象
        PublicKey publicKey = getPublicKey(IO.readPublicKeyStr());
        /*RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(IO.readPublicKeyStr())));*/

        map.put("privateKey", privateKey);
        map.put("publicKey", publicKey);
        return map;
    }

    /**
     * 生成随机的密钥对
     *
     * @return map
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static Map<String, String> generateKeyPair() throws NoSuchAlgorithmException, IOException {
        //基于RSA算法生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //初始化密钥对生成器(96-1024)
        //keyPairGenerator.initialize(Constant.KEY_SIZE,new SecureRandom());
        keyPairGenerator.initialize(3072, new SecureRandom());
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //使用密钥对生成密钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        //使用密钥对生成公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        //生成密钥字符串
        //String privateKeyStr = new String(Base64.encodeBase64(privateKey.getEncoded()));
        String privateKeyStr = new String(Base64.getEncoder().encode(privateKey.getEncoded()));
        //生成公钥字符串
        //String publicKeyStr = new String(Base64.encodeBase64(publicKey.getEncoded()));
        String publicKeyStr = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        Map<String, String> map = new HashMap<>();
        map.put("publicKey", publicKeyStr);
        map.put("privateKey", privateKeyStr);

        FileOutputStream fos = new FileOutputStream("private");
        fos.write(privateKeyStr.getBytes());
        fos.flush();
        fos.close();

        fos = new FileOutputStream("public");
        fos.write(publicKeyStr.getBytes());
        fos.flush();
        fos.close();

        return map;
    }

    /**
     * 解密
     *
     * @param cipherText 密文
     * @param key        私钥
     * @return 文本(密文解密的原文)
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String cipherText, String key) throws NoSuchAlgorithmException, InvalidKeySpecException,
            IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //64位解码后的加密后字符串
        //byte[] data = Base64.decodeBase64(cipherText.getBytes("UTF-8"));
        byte[] data = Base64.getDecoder().decode(cipherText.getBytes("UTF-8"));

        //base64编码的私钥
        //byte[] decode = Base64.decodeBase64(key);
        byte[] decode = Base64.getDecoder().decode(key);

        RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.
                getInstance("RSA").
                generatePrivate(new PKCS8EncodedKeySpec(decode));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //解密
        byte[] decryptedData = cipher.doFinal(data);

        String text = new String(decryptedData);

        return text;
    }

    /**
     * 加密
     *
     * @param key  公钥
     * @param text 文本
     * @return 密文(加密后的文本)
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(String key, String text) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {

        //base64编码的公钥
        //byte[] decodes = Base64.decodeBase64(key);
        byte[] decodes = Base64.getDecoder().decode(key);

        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decodes));

        //生成密码对象
        Cipher cipher = Cipher.getInstance("RSA");
        //密码对象初始化(加密模式、公钥)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //把文本转换成byte数组
        byte[] data = text.getBytes("UTF-8");

        //加密(得到byte数组)
        byte[] cipherBytes = cipher.doFinal(data);

        //转化为字符串(密文)
        //String cipherText = Base64.encodeBase64String(cipherBytes);
        String cipherText = Base64.getEncoder().encodeToString(cipherBytes);

        return cipherText;
    }

    /**
     * 签名处理
     *
     * @param privateKey 公钥
     * @param data       文本(初始文本/原文)
     * @return 签名(文本进行签名处理的结果)
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String sign(PrivateKey privateKey, String data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {


        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        //生成签名类对象
        Signature signature = Signature.getInstance("SHA256withRSA"); //SHA256withRSA MD5withRSA
        //初始化签名
        signature.initSign(key);
        //签名
        signature.update(data.getBytes());

        //return new String(Base64.encodeBase64(signature.sign())) ;
        return new String(Base64.getEncoder().encode(signature.sign()));
    }

    /**
     * 验签(验证签名处理)
     *
     * @param srcData   原始文本
     * @param publicKey 公钥
     * @param sign      签名
     * @return 签名是否通过
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(String srcData, PublicKey publicKey, String sign) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initVerify(key);
        signature.update(srcData.getBytes());

        //return signature.verify(Base64.decodeBase64(sign.getBytes()));
        return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
    }
}
