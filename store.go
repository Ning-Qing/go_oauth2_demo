package main

import (
	"context"
	"errors"

	"github.com/go-oauth2/oauth2/v4"
)

type Store struct {
	clientInfoData map[string]*ClientInfo
	userInfoData   map[string]*UserInfo
}

func NewStore() *Store {
	return &Store{
		clientInfoData: map[string]*ClientInfo{},
		userInfoData:   map[string]*UserInfo{},
	}
}

func (s *Store) SetClientInfo(id, secret, domain, userid string) {
	info := &ClientInfo{
		ID:     id,
		Secret: secret,
		Domain: domain,
		UserID: userid,
	}
	s.clientInfoData[id] = info
}

func (s *Store) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	info, ok := s.clientInfoData[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func (s *Store) SetUserInfo(clientID, username, password string) {
	info := &UserInfo{
		ClientID:     clientID,
		UserName:     username,
		UserPassword: password,
	}
	s.userInfoData[username] = info
}

func (s *Store) GetUserInfoByUserName(ctx context.Context, name string) (*UserInfo, error) {
	info, ok := s.userInfoData[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

type ClientInfo struct {
	ID     string
	UserID string
	Secret string
	Domain string
}

func (i *ClientInfo) GetID() string {
	return i.ID
}

func (i *ClientInfo) GetSecret() string {
	return i.Secret
}

func (i *ClientInfo) GetDomain() string {
	return i.Domain
}

func (i *ClientInfo) GetUserID() string {
	return i.UserID
}

type UserInfo struct {
	ClientID     string
	UserName     string
	UserPassword string
}
