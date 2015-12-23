// Copyright 2016 Author YuShuangqi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package main

package o2o

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/ysqi/tokenauth"
	"github.com/ysqi/tokenauth2beego"
	"net/http"
)

var Auth *O2OAutomatic

type O2OAutomatic struct {
	Audience *tokenauth.Audience
	tokenauth2beego.Automatic
}

func DefaultFileter() beego.FilterFunc {
	d := &tokenauth.DefaultProvider{}
	return NewAuthFileter(tokenauth.TokenPeriod, d.GenerateSecretString, d.GenerateTokenString)
}

func NewAuthFileter(tokenPeriod uint64, secretFunc tokenauth.GenerateSecretString, tokenFunc tokenauth.GenerateTokenString) beego.FilterFunc {
	audience := &tokenauth.Audience{
		Name:        "CusSingleTokenCheck",
		ID:          tokenauth.NewObjectId().Hex(),
		TokenPeriod: tokenPeriod,
	}
	audience.Secret = secretFunc(audience.ID)
	if Auth == nil {
		Auth = &O2OAutomatic{}
	}
	Auth.TokenFunc = tokenFunc
	Auth.Audience = audience

	return func(ctx *context.Context) {
		if _, err := Auth.CheckToken(ctx.Request); err != nil {
			Auth.ReturnFailueInfo(err, ctx)
		}
	}
}

// Get and Save a new token. this user's other token will be destory.
// Set Authorization to header,if w is not nil.
func (a *O2OAutomatic) NewSingleToken(userID string, w ...http.ResponseWriter) (token *tokenauth.Token, err error) {

	if len(userID) == 0 {
		return nil, tokenauth2beego.ERR_UserIDEmpty
	}

	// New token
	token, err = tokenauth.NewSingleToken(userID, a.Audience, a.TokenFunc)
	if err != nil {
		return
	}

	if len(w) > 0 && w[0] != nil {
		// e.g.  Authorization:access_token hJN+8GhT1RzbXStv+TIuH0KeI95hZhzMo4pdBBnuP78=
		w[0].Header().Set("Authorization", fmt.Sprintf("%s %s", tokenauth2beego.TokenFieldName, token.Value))
	}
	return
}