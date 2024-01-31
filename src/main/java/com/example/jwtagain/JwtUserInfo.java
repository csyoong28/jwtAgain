package com.example.jwtagain;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * jwt 存储的 内容
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtUserInfo implements Serializable {
    /**
     * 账号ID
     */
    private Integer userId;

    /**
     * 当前登录人单位组织ID
     */
    private Integer orgId;
}

