# Tokenauth2beego
使用`github.com/ysqi/tokenauth`给 Beego 写的 token 验证插件，支持多种方式验证。

# 安装
```shell
go get github.com/ysqi/tokenauth2beego
```

# TokenAuth包介绍
具体信息请参考 [`TokenAuth Readme.md`][TokenAuthDoc]

# 功能
+ 支持原生 TokenAuth 包功能，具体见[`TokenAuth ReadeMe.md`][TokenAuthDoc]
+ 支持 HTTP Header 验证
+ 支持 HTTP Get,Post 等传参验证

# TODO
+ 实现 Cookie Token验证
+ 实现 Beego ORM 维护多 Client 信息
+ 实现验证通过后Token信息传递

# 基础使用
```go
import(
    "github.com/astaxie/beego"
    "github.com/ysqi/tokenauth2beego/o2o"
)

func main(){
    // authenticate every request
    beego.InsertFilter("*", beego.BeforeRouter, o2o.DefaultFileter())
    beego.Run()
}
```
在用户登录成功后写入 Token
```go
token, err := o2o.Auth.NewSingleToken(userID,responseWriter)
```

# 示例1
在 Web 站点中当用户成功后通过 Token 进行权限验证（待提供）

# 示例2
下载站点资源时限制有效期限（待提供）

# 示例3
Beego API 应用通过Token进行权限验证（待提供）

# 示例4
多站点单点登录

# LICENSE
该包在Apache Licence, Version 2.0协议下使用 (http://www.apache.org/licenses/LICENSE-2.0.html).





[TokenAuthDoc]:https://github.com/ysqi/tokenauth/blob/master/README.md
