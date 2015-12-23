// Package auth provides handlers to enable basic auth support.
// Example:
//	import(
//		"github.com/astaxie/beego"
//		"github.com/ysqi/tokenauth2beego/o2o"
//	)
//
//	func main(){
//		// authenticate every request
//		beego.InsertFilter("*", beego.BeforeRouter, o2o.DefaultFileter())
//		beego.Run()
//	}
//
//
// Save and Get SingleToken Token:
//	  token, err := o2o.Auth.NewSingleToken(userID)
//
package tokenauth2beego

import (
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/ysqi/tokenauth"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

var (
	ERR_ServerError = tokenauth.ValidationError{Code: "-1", Msg: "System error , Please retry"}
	ERR_UserIDEmpty = tokenauth.ValidationError{Code: "41020", Msg: "UserID is empty"}
)

const (
	TokenFieldName = "access_token"
)

func init() {

	// Get Config
	confs, _ := beego.AppConfig.GetSection("tokenauth")

	// Defaul value.
	storeName := "default"
	storeConf := ""

	// If exist config.
	if len(confs) > 0 {
		if v, ok := confs["storename"]; ok {
			storeName = v
		}
		if v, ok := confs["storeconf"]; ok {
			storeConf = v
		}
		if v, ok := confs["tokenperiod"]; ok {
			if period, err := strconv.ParseUint(v, 10, 64); err != nil {
				beego.Warn(fmt.Sprintf("tokenauth: config[tokenauth.tokenperiod]=%q convert to uint fail, use default value %d,%s", v, tokenauth.TokenPeriod, err))
			} else {
				if period == 0 {
					beego.Warn("tokenauth: config[tokenauth.tokenperiod] is zero , all token will never expires")
				}
				tokenauth.TokenPeriod = period
			}
		}
	}

	// Set db path if store config is emtpy when use default store
	if storeName == "default" && len(storeConf) == 0 {
		if err := tokenauth.UseDeaultStore(); err != nil {
			panic(err)
		}
	} else {

		// Init and Use Store
		if store, err := tokenauth.NewStore(storeName, storeConf); err != nil {
			panic(err)
		} else if err = tokenauth.ChangeTokenStore(store); err != nil {
			panic(err)
		}
	}

	// Keep close db when process exsit.
	deferCloseStore()
}

// Define event to close Store
func deferCloseStore() {
	go func() {
		c := make(chan os.Signal, 1)
		// get ^C and process kill signal.
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		// Close store when exit
		if tokenauth.Store != nil {
			tokenauth.Store.Close()
		}
	}()
}

type Automatic struct {
	TokenFunc  tokenauth.GenerateTokenString
	SecretFunc tokenauth.GenerateSecretString
}

// Check User Token from reqeust.
// First find Authorization from reqeust hearder,
// Then find access_token from reqeust form field.
// Returns effective token or error.
func (a *Automatic) CheckToken(req *http.Request) (token *tokenauth.Token, err error) {

	tokenString := ""
	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); len(ah) > 0 {
		// Should be a access token
		fieldLen := len(TokenFieldName)
		if len(ah) > fieldLen+1 && ah[fieldLen] == ' ' && strings.HasPrefix(ah, TokenFieldName) {
			tokenString = ah[fieldLen+1:]
		}
	}

	// Look for "access_token" parameter
	if len(tokenString) == 0 {
		if req.Form == nil {
			req.ParseMultipartForm(10e6)
		}
		if tokStr := req.Form.Get(TokenFieldName); tokStr != "" {
			tokenString = tokStr
		}

	}
	if len(tokenString) == 0 {
		return nil, tokenauth.ERR_TokenEmpty
	}
	// Get token.
	token, err = tokenauth.ValidateToken(tokenString)
	return
}

// Write error info to response and abort request.
// e.g. response body:
// 	{"errcode":"41001","errmsg":"Token is emtpy"}
func (a *Automatic) ReturnFailueInfo(err error, ctx *context.Context) {

	if err == nil {
		return
	}

	errInfo, ok := err.(tokenauth.ValidationError)
	if !ok {
		errInfo = ERR_ServerError
		if beego.RunMode == "dev" {
			errInfo.Msg = fmt.Sprintf("%s,%s", errInfo.Msg, err.Error())
		}
	}

	hasIndent := false
	if beego.RunMode == "dev" {
		hasIndent = true
	}

	if ctx.Input.AcceptsXml() {
		ctx.Output.Xml(errInfo, hasIndent)
	} else {
		ctx.Output.Json(errInfo, hasIndent, false)
	}
}