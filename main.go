package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt"
)

func main() {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	server := NewServer()

	router.POST("/registered", server.Registered)
	router.POST("/login", server.Login)
	router.POST("/secret", server.Secret)
	router.POST("/access_token", server.AccessToken)
	router.POST("/refresh_token", server.Referer)

	g := router.Group("/test").Use(HandleTokenVerify(server.ValidationBearerToken()))
	{
		g.GET("/authorization", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "ok")
		})
		g.GET("/access_token", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "ok")
		})
	}

	http.ListenAndServe(":8080", router)
}

type Server struct {
	store       *Store
	oauthServer *server.Server
}

func NewServer() *Server {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	tokenStore, err := store.NewMemoryTokenStore()
	if err != nil {
		log.Fatal(err)
	}
	manager.MapTokenStorage(tokenStore)

	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("auth", []byte("vone-bfs"), jwt.SigningMethodHS512))

	store := NewStore()
	manager.MapClientStorage(store)

	oauthSrv := server.NewServer(server.NewConfig(), manager)
	oauthSrv.SetPasswordAuthorizationHandler(PasswordAuthorizationHandler(store))
	oauthSrv.SetClientInfoHandler(ClientInfoHandler(tokenStore, store))

	return &Server{
		store:       store,
		oauthServer: oauthSrv,
	}
}

func (s *Server) Registered(ctx *gin.Context) {
	s.store.SetClientInfo("test", "test-secret", "", "")
	s.store.SetUserInfo("test", "test", "test")
}

func (s *Server) Login(ctx *gin.Context) {
	err := s.oauthServer.HandleTokenRequest(ctx.Writer, ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
}

func (s *Server) Secret(ctx *gin.Context) {
	s.store.SetClientInfo("test2", "test-secret2", "", "")
}

func (s *Server) AccessToken(ctx *gin.Context) {
	err := s.oauthServer.HandleTokenRequest(ctx.Writer, ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
}

func (s *Server) Referer(ctx *gin.Context) {
	err := s.oauthServer.HandleTokenRequest(ctx.Writer, ctx.Request)
	if err != nil {
		ctx.Error(err)
		return
	}
}

func (s *Server) ValidationBearerToken() ValidationFunc {
	return s.oauthServer.ValidationBearerToken
}
