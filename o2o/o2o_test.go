// Copyright 2016 Author YuShuangqi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.package main

package o2o_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"encoding/json"
	"errors"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/ysqi/tokenauth"
	"github.com/ysqi/tokenauth2beego"
	"github.com/ysqi/tokenauth2beego/o2o"
	. "gopkg.in/check.v1"
	"net/url"
	"os"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type S struct{}

var _ = Suite(&S{})

var handler *beego.ControllerRegistor

func (s *S) SetUpSuite(c *C) {

	handler = beego.NewControllerRegister()
	handler.InsertFilter("/user/*", beego.BeforeRouter, o2o.DefaultFileter())
	handler.Any("*", func(ctx *context.Context) {
		ctx.WriteString("OK")
	})
}

func (s *S) TearDownSuite(c *C) {
	tokenauth.Store.Close()
	if store, ok := tokenauth.Store.(*tokenauth.BoltDBFileStore); ok {
		if err := os.Remove(store.DBPath()); err != nil {
			c.Fatalf("Remove Test db file %q fail,%s", store.DBPath(), err.Error())
		}
	}
}

func (s *S) Test_NewSingleToken(c *C) {

	userID := "ysqi"
	token, err := o2o.Auth.NewSingleToken(userID)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)

	token, err = o2o.Auth.NewSingleToken("")
	c.Assert(err, DeepEquals, tokenauth2beego.ERR_UserIDEmpty)
	c.Assert(token, IsNil)

	recorder := httptest.NewRecorder()
	token, err = o2o.Auth.NewSingleToken(userID, recorder)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)
}

func (s *S) Test_Empty(c *C) {
	recorder := httptest.NewRecorder()

	r, _ := http.NewRequest("PUT", "/user/info", nil)
	handler.ServeHTTP(recorder, r)
	bodyStr := recorder.Body.String()
	c.Assert(paseToError(bodyStr), DeepEquals, tokenauth.ERR_TokenEmpty)

}

func (s *S) Test_ErrorToken_01(c *C) {

	r, _ := http.NewRequest("PUT", "/user/info", nil)
	r.Header.Set("Authorization", "")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	bodyStr := recorder.Body.String()
	c.Assert(paseToError(bodyStr), DeepEquals, tokenauth.ERR_TokenEmpty)

}

func (s *S) Test_ErrorToken_02(c *C) {

	r, _ := http.NewRequest("PUT", "/user/info", nil)
	r.Header.Set("Authorization", fmt.Sprintf("%s=", tokenauth2beego.TokenFieldName))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	bodyStr := recorder.Body.String()
	c.Assert(paseToError(bodyStr), DeepEquals, tokenauth.ERR_TokenEmpty)
}

func (s *S) Test_ErrorToken_03(c *C) {

	r, _ := http.NewRequest("PUT", "/user/info", nil)
	r.Header.Set("Authorization", tokenauth2beego.TokenFieldName)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	bodyStr := recorder.Body.String()
	c.Assert(paseToError(bodyStr), DeepEquals, tokenauth.ERR_TokenEmpty)
}

func (s *S) Test_ErrorToken_04(c *C) {

	r, _ := http.NewRequest("PUT", "/user/info", nil)
	r.Header.Set("Authorization", fmt.Sprintf("%s tokenvalue", tokenauth2beego.TokenFieldName))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	bodyStr := recorder.Body.String()
	c.Assert(paseToError(bodyStr), DeepEquals, tokenauth.ERR_InvalidateToken)
}

func (s *S) Test_RealToken_Header(c *C) {

	userID := "ysqi"
	recorder := httptest.NewRecorder()
	token, err := o2o.Auth.NewSingleToken(userID, recorder)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)
	c.Assert(recorder.Header().Get("Authorization"), Not(Equals), "")

	r, _ := http.NewRequest("PUT", "/user/ok", nil)
	r.Header.Set("Authorization", recorder.Header().Get("Authorization"))
	handler.ServeHTTP(recorder, r)

	bodyStr := recorder.Body.String()
	c.Assert(bodyStr, Equals, "OK")
}

func (s *S) Test_RealToken_FromPost(c *C) {

	userID := "ysqi"
	recorder := httptest.NewRecorder()
	token, err := o2o.Auth.NewSingleToken(userID, recorder)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)

	v := url.Values{}
	v.Set("access_token", token.Value)
	r, _ := http.NewRequest("PUT", "/user/ok", nil)
	r.Form = v

	handler.ServeHTTP(recorder, r)

	bodyStr := recorder.Body.String()
	c.Assert(bodyStr, Equals, "OK")
}

func (s *S) Test_RealToken_FromGet(c *C) {

	userID := "ysqi"
	recorder := httptest.NewRecorder()
	token, err := o2o.Auth.NewSingleToken(userID, recorder)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)

	r, _ := http.NewRequest("PUT", "/user/ok?access_token="+token.Value, nil)
	handler.ServeHTTP(recorder, r)

	bodyStr := recorder.Body.String()
	c.Assert(bodyStr, Equals, "OK")
}

func (s *S) Test_RealToken_FromCookie(c *C) {

	tokenauth2beego.EnableCookie = true

	userID := "ysqi"
	recorder := httptest.NewRecorder()
	token, err := o2o.Auth.NewSingleToken(userID, recorder)
	c.Assert(err, IsNil)
	c.Assert(token, NotNil)
	cookieInfo := recorder.Header().Get("Set-Cookie")
	c.Assert(cookieInfo, Not(Equals), "")

	r, _ := http.NewRequest("PUT", "/user/ok", nil)
	r.AddCookie(o2o.Auth.ConvertoCookie(token))
	handler.ServeHTTP(recorder, r)

	bodyStr := recorder.Body.String()
	c.Assert(bodyStr, Equals, "OK")
}

func paseToError(str string) error {

	if len(str) == 0 {
		return errors.New("")
	}

	var item tokenauth.ValidationError
	if json.Unmarshal([]byte(str), &item) == nil {
		return item
	}

	return errors.New(str)

}
