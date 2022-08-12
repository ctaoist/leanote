package info

import "time"

type KeepAliveCookie struct {

	/**
	 * 创建时间
	 */
	CreateTime time.Time `json:"create_time" bson:"create_time"`
	/**
	 * 过期时间
	 */
	ExpireTime time.Time `json:"expire_time" bson:"expire_time"`
	/**
	 * 登录IP地址
	 */
	ClientIP string `json:"client_ip" bson:"client_ip"`
	/**
	 * Token值
	 */
	Token string `json:"token" bson:"token"`
	/**
	 * 绑定的用户名
	 */
	Username string `json:"username" bson:"username"`
	/**
	 * 客户端ID
	 */
	ClientID string `json:"client_id" bson:"client_id"`
}
