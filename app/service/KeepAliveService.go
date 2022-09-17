package service

import (
	"github.com/google/uuid"
	"github.com/leanote/leanote/app/db"
	"github.com/leanote/leanote/app/info"
	"github.com/revel/revel"
	"github.com/thinkeridea/go-extend/exnet"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

type KeepAliveService struct {
}

const XClientIdHeaderName = "x-client-id"
const KeepaliveCookieName = "keepalive"

func clearCookie(c *revel.Controller) {
	c.SetCookie(&http.Cookie{Name: KeepaliveCookieName, MaxAge: -1, Path: "/"})
}

func setKeepaliveCookie(c *revel.Controller, token string, expiresTime time.Time) {
	c.SetCookie(&http.Cookie{Name: KeepaliveCookieName, Value: token, Expires: expiresTime, Path: "/"})
}

func tryRemoveKeepaliveCookie(c *revel.Controller) {
	_, err := c.Request.Cookie(KeepaliveCookieName)

	if err != nil {
		return
	}

	clearCookie(c)
}

func (s KeepAliveService) TryRemoveKeepalive(c *revel.Controller) {
	cookie, err := c.Request.Cookie(KeepaliveCookieName)

	if err != nil {
		return
	}

	tokens := cookie.GetValue()

	_, err = db.KeepAliveTokens.RemoveAll(bson.M{"token": tokens})

	clearCookie(c)
}

func (s KeepAliveService) Auth(c *revel.Controller, user *info.User) bool {
	clientId := c.Request.GetHttpHeader(XClientIdHeaderName)

	if clientId == "" { // 未提供`ClientID`不能认证
		c.Log.Info("[Cookie-Auth]: client-id is null")
		return false
	}

	//
	stored := info.KeepAliveCookie{}

	if !getCookieByClientID(clientId, &stored) {
		return false
	}

	cookie, err := c.Request.Cookie(KeepaliveCookieName)

	if err != nil {
		c.Log.Warn("[Cookie-Auth]: token cookie is empty")

		return false
	}

	token := cookie.GetValue()

	if token != stored.Token {
		c.Log.Warn("[Cookie-Auth]: token verify failed")

		clearCookie(c)

		return false
	}

	clientIP := exnet.ClientIP(c.Request.In.GetRaw().(*http.Request))

	if clientIP != stored.ClientIP {
		c.Log.Warn("[Cookie-Auth]: client ip changed")

		clearCookie(c)

		return false
	}

	if time.Now().After(stored.ExpireTime) {
		c.Log.Warn("[Cookie-Auth]: cookie is expired")

		clearCookie(c)

		return false
	}

	localUser := userService.GetUserInfoByUsername(stored.Username)

	if localUser.Username == "" { // 绑定的用户不存在
		c.Log.Warn("[Cookie-Auth]: bind user not found")

		return false
	}

	*user = localUser

	return true
}

func (s *KeepAliveService) GetKeepaliveByToken(token string) (info.KeepAliveCookie, bool) {
	query := bson.M{"Token": token}

	cookie := info.KeepAliveCookie{}
	err := db.KeepAliveTokens.Find(query).One(&cookie)

	if err != nil {
		return cookie, false
	} else {
		return cookie, true
	}
}

func getCookieByClientID(clientID string, keepAlive *info.KeepAliveCookie) bool {
	err := db.KeepAliveTokens.Find(bson.M{
		"clientid": clientID,
	}).One(keepAlive)

	return err == nil
}

func setExpireTime(cookie *info.KeepAliveCookie) {
	days := revel.Config.IntDefault("keepalive.days", 7)

	cookie.CreateTime = time.Now()
	cookie.ExpireTime = time.Now().Add(time.Duration(days*24) * time.Hour)
}

// @title 尝试更新cookie值
// @description   						更新数据库中的token值
// @param c *revel.Controller 			控制器
// @param stored *info.KeepAliveCookie  已保存的cookie值
// @param message *info.KeepAliveCookie 登录信息
func tryUpdateCookie(c *revel.Controller, stored *info.KeepAliveCookie, message *info.KeepAliveCookie, clientID string) bool {
	token, err := uuid.NewUUID()

	if err != nil {
		return false
	}

	// 生成新的token值
	stored.Token = token.String()
	stored.ClientIP = exnet.ClientIP(c.Request.In.GetRaw().(*http.Request))
	stored.Username = message.Username
	stored.ClientID = clientID

	setExpireTime(stored)

	if db.Update(db.KeepAliveTokens, bson.M{"clientid": clientID}, stored) {
		setKeepaliveCookie(c, stored.Token, stored.ExpireTime)

		return true
	}

	clearCookie(c)

	return false
}

func tryAddKeepaliveCookie(c *revel.Controller, message *info.KeepAliveCookie, clientID string) bool {
	token, err := uuid.NewUUID()

	if err != nil {
		return false
	}

	message.Token = token.String()
	setExpireTime(message)
	message.ClientID = clientID
	message.ClientIP = exnet.ClientIP(c.Request.In.GetRaw().(*http.Request))

	if db.Insert(db.KeepAliveTokens, message) {
		setKeepaliveCookie(c, message.Token, message.ExpireTime)

		return true
	} else {
		clearCookie(c)

		return false
	}
}

func tryUpdateKeepaliveCookie(c *revel.Controller, keepAlive *info.KeepAliveCookie, clientID string) bool {
	// 当前已保存的cookie
	store := info.KeepAliveCookie{}

	if !getCookieByClientID(clientID, &store) {
		return tryAddKeepaliveCookie(c, keepAlive, clientID)
	}

	return tryUpdateCookie(c, &store, keepAlive, clientID)
}

func (s *KeepAliveService) SetKeepAlive(c *revel.Controller, keepAlive *info.KeepAliveCookie) bool {
	// 删除`cookie`
	keepalive := c.Params.Get("keepalive")
	//
	c.Log.Debug("[Cookie-Auth]: keepalive parameter value: " + keepalive)

	if keepalive != "true" {
		tryRemoveKeepaliveCookie(c)

		return false
	}

	clientId := c.Request.GetHttpHeader(XClientIdHeaderName)

	if clientId == "" { // 未提供`ClientID`不能认证
		return false
	}

	return tryUpdateKeepaliveCookie(c, keepAlive, clientId)
}
