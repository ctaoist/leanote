package info

import "time"

type KeepAliveCookie struct {

	/**
	 * 创建时间
	 */
	CreateTime time.Time `CreateTime:"create_time"`
	/**
	 * 过期时间
	 */
	ExpireTime time.Time `ExpireTime:"expire_time"`
	/**
	 * 登录IP地址
	 */
	ClientIP string `ClientIP:"client_ip"`
	/**
	 * Token值
	 */
	Token string `Token:"token"`
	/**
	 * 绑定的用户名
	 */
	Username string `Username:"username"`
	/**
	 * 客户端ID
	 */
	ClientID string `ClientID:"client_id"`
}
