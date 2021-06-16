/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.security;


import java.io.*;

/**
 * 使用io流从外部文件获取密钥、公钥
 *
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2020/9/12 21:36:07
 */
public class IO {

    /**
     * 从外部文件中读取公钥
     *
     * @return 公钥字符串
     * @throws IOException
     */
    public static String readPublicKeyStr() throws IOException {

        FileInputStream fis = new FileInputStream("public");
        int readCount;
        String publicKeyStr = "";
        byte[] bytes = new byte[3072];
        while ((readCount = fis.read(bytes)) != -1) {
            publicKeyStr = new String(bytes, 0, readCount);
        }
        fis.close();
        return publicKeyStr;
    }

    /**
     * 从外部文件中读取密钥
     *
     * @return 密钥字符串
     * @throws IOException
     */
    public static String readPrivateKeyStr() throws IOException {

        FileInputStream fis = new FileInputStream("private");
        int readCount;
        String publicKeyStr = "";
        byte[] bytes = new byte[3072];
        while ((readCount = fis.read(bytes)) != -1) {
            publicKeyStr = new String(bytes, 0, readCount);
        }
        fis.close();
        return publicKeyStr;
    }


}
