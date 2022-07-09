/*
 *Copyright @2022 Grapefruit. All rights reserved.
 */

package com.grapefruit.utils.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 日志
 *
 * @author 柚子苦瓜茶
 * @version 1.0
 * @ModifyTime 2022/07/09 21:36:07
 */
public class LogTools {
    public static Logger getSendLogger() {
        return LoggerFactory.getLogger("send");
    }

    public static Logger getReceiveLogger() {
        return LoggerFactory.getLogger("receive");
    }
}
