package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
)

func PasswordAuthorizationHandler(store *Store) server.PasswordAuthorizationHandler {
	return func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		info, err := store.GetUserInfoByUserName(context.TODO(), username)
		if err != nil {
			return "", err
		}
		if info.UserPassword == password {
			return username, nil
		}
		return "", errors.New("the username or password is incorrect")
	}
}

func ClientInfoHandler(tokenStore oauth2.TokenStore, store *Store) server.ClientInfoHandler {
	return func(r *http.Request) (clientID string, clientSecret string, err error) {
		gt := oauth2.GrantType(r.FormValue("grant_type"))
		switch gt {
		case oauth2.AuthorizationCode:
		case oauth2.PasswordCredentials:
			username, password := r.FormValue("username"), r.FormValue("password")
			if username == "" || password == "" {
				return "", "", errors.New("the user name or password is blank")
			}
			// 通过用户名和密码获取clientID,clientSecret
			userInfo, err := store.GetUserInfoByUserName(context.TODO(), username)
			if err != nil {
				return "", "", err
			}
			clientInfo, err := store.GetByID(context.TODO(), userInfo.ClientID)
			if err != nil {
				return "", "", err
			}
			return clientInfo.GetID(), clientInfo.GetSecret(), nil
		case oauth2.ClientCredentials:
			// 通过client_id查询密钥再校验
			clientID := r.FormValue("client_id")
			if clientID == "" {
				return "", "", errors.New("not found client id")
			}
			clientInfo, err := store.GetByID(context.TODO(), clientID)
			if err != nil {
				return "", "", err
			}
			clientSecret := r.FormValue("client_secret")
			if clientSecret == clientInfo.GetSecret() {
				return clientID, clientSecret, nil
			}
			return "", "", errors.New("the client id or client secret is incorrect")
		case oauth2.Refreshing:
			refreshToken := r.FormValue("refresh_token")
			tokenInfo, err := tokenStore.GetByRefresh(context.TODO(), refreshToken)
			if err != nil {
				return "", "", err
			}
			clientInfo, err := store.GetByID(context.TODO(), tokenInfo.GetClientID())
			if err != nil {
				return "", "", err
			}
			return clientInfo.GetID(), clientInfo.GetSecret(), nil
		}
		return "", "", errors.New("not found")
	}
}
