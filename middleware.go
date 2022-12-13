package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
)

type ValidationFunc func(r *http.Request) (oauth2.TokenInfo, error)

const tokenInfoKey = "token_info"

func HandleTokenVerify(vaild ValidationFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenInfo, err := vaild(ctx.Request)
		if err != nil {
			ctx.AbortWithError(http.StatusNonAuthoritativeInfo, err)
		}
		ctx.Set(tokenInfoKey, tokenInfo)
		ctx.Next()
	}
}
