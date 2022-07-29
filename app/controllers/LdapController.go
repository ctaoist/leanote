package controllers

import (
	"github.com/go-ldap/ldap"
	"github.com/leanote/leanote/app/info"
	"github.com/revel/cmd/utils"
	"github.com/revel/revel"
	"gopkg.in/mgo.v2/bson"
	"strings"
	"time"
)

type LdapAuth struct {
	BaseController
}

func (c LdapAuth) LdapLoginView(username, from string) revel.Result {
	enable := revel.Config.BoolDefault("ldap.enable", false)

	if !enable { // ldap认证功能被禁用
		return c.Redirect("/login")
	}

	host, _ := revel.Config.String("ldap.host")

	if host == "" { // 未配置认证地址则返回首页
		return c.Redirect("/login")
	}

	c.ViewArgs["title"] = c.Message("ldapLoginTitle")
	c.ViewArgs["subTitle"] = c.Message("login")
	c.ViewArgs["email"] = username
	c.ViewArgs["from"] = from

	sessionId := c.Session.ID()
	if sessionService.LoginTimesIsOver(sessionId) {
		c.ViewArgs["needCaptcha"] = true
	}

	c.SetLocale()

	return c.RenderTemplate("home/ldap/login.html")
}

func (c LdapAuth) LdapLogin(username string, password string) revel.Result {
	enable := revel.Config.BoolDefault("ldap.enable", false)

	if !enable { // ldap认证功能被禁用
		return c.Redirect("/login")
	}

	host, _ := revel.Config.String("ldap.host")

	sessionId := c.Session.ID()

	if sessionService.LoginTimesIsOver(sessionId) {
		c.ViewArgs["needCaptcha"] = true
	}

	if host == "" {
		utils.Logger.Warn("[ldap]: 未提供认证服务器主机地址")

		return c.RenderJSON(info.Re{Ok: false, Item: sessionService.LoginTimesIsOver(sessionId), Msg: c.Message("ldapUnavailable")})
	}

	conn, err := ldap.Dial("tcp", host)

	var msg = "loginFailure"

	if err != nil {
		utils.Logger.Warn("[ldap]: 连接'" + host + "'失败")

		return c.RenderJSON(info.Re{Ok: false, Item: sessionService.LoginTimesIsOver(sessionId), Msg: c.Message(msg)})
	}

	baseDN := revel.Config.StringDefault("ldap.baseDN", "")
	cnName := revel.Config.StringDefault("ldap.cnName", "cn")

	var userDN = cnName + "=" + username

	if baseDN != "" {
		userDN += "," + baseDN
	}

	err = conn.Bind(userDN, password)

	if err != nil {
		utils.Logger.Warn("[ldap]: '" + userDN + "'认证失败")

		return c.RenderJSON(info.Re{Ok: false, Item: sessionService.LoginTimesIsOver(sessionId), Msg: c.Message(msg)})
	}

	userInfo := userService.GetUserInfoByName(username)

	if userInfo.UserId != "" {
		c.SetSession(userInfo)

		sessionService.ClearLoginTimes(sessionId)

		return c.RenderJSON(info.Re{Ok: true})
	}

	// 数据库中该用户不存在，则尝试创建本地用户
	userInfo = info.User{}
	userInfo.ThirdUserId = "ldap"
	userInfo.ThirdUsername = strings.ToLower(username)
	userInfo.CreatedTime = time.Now()
	userInfo.UsernameRaw = username
	userInfo.UserId = bson.NewObjectId()

	if userService.AddUser(userInfo) {
		c.SetSession(userInfo)

		sessionService.ClearLoginTimes(sessionId)

		return c.RenderJSON(info.Re{Ok: true})
	}

	return c.RenderJSON(info.Re{Ok: false, Item: sessionService.LoginTimesIsOver(sessionId), Msg: c.Message("ldapUserBindFail")})
}
