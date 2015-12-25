// Copyright 2016 Author YuShuangqi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package main

// Package one client with one more tokens.
package o2m

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/ysqi/tokenauth"
	"github.com/ysqi/tokenauth2beego"
	"net/http"
	"strings"
)

var Auth *O2MAutomatic

type O2MAutomatic struct {
	tokenauth2beego.Automatic
}

func DefaultFileter() beego.FilterFunc {
	d := &tokenauth.DefaultProvider{}
	return NewAuthFileter(tokenauth.TokenPeriod, d.GenerateSecretString, d.GenerateTokenString)
}

func NewAuthFileter(secretFunc tokenauth.GenerateSecretString, tokenFunc tokenauth.GenerateTokenString) beego.FilterFunc {

	if Auth == nil {
		Auth = &Automatic{}
	}
	Auth.TokenFunc = tokenFunc
	Auth.SecretFunc = secretFunc

	return func(ctx *context.Context) {
		if _, err := Auth.CheckToken(ctx.Request); err != nil {
			Auth.ReturnFailueInfo(err, ctx)
		}
	}
}

// Get a new Clinet Info.
// ClientName just client description info.
// You need save client info for get client info from store once again.
func (a *O2MAutomatic) NewClient(clientName string) (*tokenauth.Audience, error) {
	return tokenauth.NewAudience(clientName, a.SecretFunc)
}

// Get client info from store by clientID.
// Returns exist client info or error.
func (a *O2MAutomatic) GetClient(clientID string) (*tokenauth.Audience, error) {
	return tokenauth.Store.GetAudience(clientID)
}

// Get and Save a new client token.
// Set Authorization to header,if w is not nil.
func (a *O2MAutomatic) NewClientTokenByClientID(clientID string, w ...http.ResponseWriter) (token *tokenauth.Token, err error) {

	var client *tokenauth.Audience
	client, err = a.GetClient(clientID)
	if err != nil {
		return
	}
	return a.NewClientToken(client, w)
}

// Get and Save a new client token.
// Set Authorization to header,if w is not nil.
func (a *O2MAutomatic) NewClientToken(client *tokenauth.Audience, w ...http.ResponseWriter) (token *tokenauth.Token, err error) {

	// New token
	token, err = tokenauth.NewToken(client, a.TokenFunc)
	if err != nil {
		return
	}

	if len(w) > 0 {
		a.SetTokenString(token, w[0])
	}
	return
}
