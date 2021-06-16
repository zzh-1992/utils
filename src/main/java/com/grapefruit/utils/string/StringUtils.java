/*
 *Copyright @2021 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.string;

import java.util.UUID;

/**
 * 相关描述
 *
 * @author zhihuangzhang
 * @version 1.0
 * @date 2021-06-16 10:07 下午
 */
public class StringUtils {
    public String getUUID() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 20);
    }
}
