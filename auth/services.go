package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Services stores supported external oauth2 services.
type Services struct {
	services map[string]*ServiceOauth
	states   *stateStorage
}

type stateStorage struct {
	storage map[string]string
	m       sync.Mutex
}

// ServiceOauth is config for specific service.
type ServiceOauth struct {
	name  string
	oauth *oauth2.Config
	fn    func(token string) (*http.Request, error)
}

type userInfoFn func(token string) (*http.Request, error)

// NewServices creates services storage using config.
func NewServices(configs map[string]*ServiceOauth) *Services {
	return &Services{
		services: configs,
		states:   newStateStorage(),
	}
}

func newStateStorage() *stateStorage {
	return &stateStorage{storage: make(map[string]string)}
}

// NewServiceConfig creates config for supported services.
func NewServiceConfig(name string, oauth *oauth2.Config) (*ServiceOauth, error) {
	var fn userInfoFn
	switch name {
	case "google":
		fn = googleRequest
	case "github":
		fn = githubRequest
	default:
		return nil, fmt.Errorf("unsupported service %s", name)
	}

	return &ServiceOauth{name, oauth, fn}, nil
}

// AddState saves new state to auth into storage.
func (s *Services) AddState(state, service string) {
	s.states.m.Lock()
	s.states.storage[state] = service
	s.states.m.Unlock()
}

// RemoveState gets and deletes used state from storage.
func (s *Services) RemoveState(state string) (string, error) {
	s.states.m.Lock()
	defer s.states.m.Unlock()
	service, ok := s.states.storage[state]
	if !ok {
		return "", fmt.Errorf("invalid oauth state")
	}
	delete(s.states.storage, state)
	return service, nil
}

// Oauth gets config for specified service.
func (s *Services) Oauth(service string) (*ServiceOauth, bool) {
	config, ok := s.services[service]
	return config, ok
}

// AuthCodeURL gets URL to auth on external service using state.
func (c *ServiceOauth) AuthCodeURL(state string) string {
	return c.oauth.AuthCodeURL(state)
}

// Exchange gets auth token after authorization.
func (c *ServiceOauth) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.oauth.Exchange(ctx, code)
}

// GetUserEmail receives user email after authentication on external service.
func (c *ServiceOauth) GetUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := c.fn(token.AccessToken)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)

	client := http.DefaultClient
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed reading response body: %s", err.Error())
	}

	emailStruct := &struct {
		Email string `json:"email"`
	}{}

	if err = json.Unmarshal(contents, emailStruct); err != nil {
		return "", err
	}

	return emailStruct.Email, nil
}

func googleRequest(token string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo?access_token="+token, nil)
}

func githubRequest(token string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+token)
	return req, nil
}
