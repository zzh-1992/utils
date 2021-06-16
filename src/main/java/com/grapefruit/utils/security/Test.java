/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;

import java.io.*;
import java.security.*;
import java.security.spec.*;

/**
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2020/9/9 19:21:10
 */
public class Test {

    public static void main(String[] args) throws InterruptedException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        checkWithHMAC256();

        checkWithHRSA512();
    }
    public static void checkWithHMAC256() throws InterruptedException {
        String token = TokenUtils.generateTokenWithHMAC256("ZZH","6789",1000L);
        Thread.sleep(1001L);

        //校验token的时候让当前线程休眠
        long l1 = System.currentTimeMillis();
        boolean isOk = TokenUtils.checkTokenWithHMAC256(token);
        long l2 = System.currentTimeMillis();

        System.out.println("解密时间:" + (l2 - l1) + "毫秒");
        System.out.println(isOk?"token有效":"token过期=====");
        TokenUtils.getContentFromToken(token);
    }

    public static void checkWithHRSA512() throws InterruptedException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String token = TokenUtils.generateTokenWithRSA512("ZZH", "123456", 2001L);
        Thread.sleep(1900L);

        //校验token的时候让当前线程休眠
        long l1 = System.currentTimeMillis();
        boolean isOk = TokenUtils.checkTokenWithRSA512(token);
        long l2 = System.currentTimeMillis();

        System.out.println("解密时间:" + (l2 - l1) + "毫秒");
        System.out.println(isOk?"token有效":"token过期=====");
        TokenUtils.getContentFromToken(token);
    }
}
