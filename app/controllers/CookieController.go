package controllers

import (
	"github.com/leanote/leanote/app/info"
	"github.com/revel/revel"
)

type CookieAuth struct {
	BaseController
}

func (c CookieAuth) DoLogin() revel.Result {
	if c.HasLogined() {
		return c.RenderJSON(info.Re{Ok: true})
	}

	user := info.User{}

	if keepAliveService.Auth(c.BaseController.Controller, &user) {
		c.SetSession(user)

		return c.RenderJSON(info.Re{Ok: true})
	}

	return c.RenderJSON(info.Re{Ok: false})
}
