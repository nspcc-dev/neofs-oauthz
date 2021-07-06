package auth

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/nspcc-dev/neofs-api-go/pkg/client"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/neofs"
	"github.com/nspcc-dev/neofs-send-authz/bearer"
	"go.uber.org/zap"
)

//go:embed static/index.html
var indexHTML string

// Authenticator is an auth requests handler.
type Authenticator struct {
	log           *zap.Logger
	plant         neofs.ClientPlant
	generator     *bearer.Generator
	config        *Config
	services      *Services
	templateModel model
}

// Config for authenticator handler.
type Config struct {
	Bearer      *bearer.Config
	Oauth       map[string]*ServiceOauth
	TLSEnabled  bool
	Host        string
	Gateway     string
	ContainerID string
	RedirectURL string
}

type model struct {
	GatewayURL  string
	ContainerID string
}

// New creates authenticator using config.
func New(log *zap.Logger, plant neofs.ClientPlant, config *Config) (*Authenticator, error) {
	return &Authenticator{
		log:       log,
		plant:     plant,
		config:    config,
		generator: bearer.NewGenerator(config.Bearer),
		services:  NewServices(config.Oauth),
		templateModel: model{
			ContainerID: config.ContainerID,
			GatewayURL:  config.Gateway,
		},
	}, nil
}

// Index is main page handler.
func (u *Authenticator) Index(w http.ResponseWriter, _ *http.Request) {
	_, err := fmt.Fprint(w, indexHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// LogInWith is an auth using external services handler.
func (u *Authenticator) LogInWith(w http.ResponseWriter, r *http.Request) {
	keys, ok := r.URL.Query()["service"]

	if !ok || len(keys[0]) < 1 {
		http.Error(w, "no valid service param", http.StatusBadRequest)
		return
	}

	serviceName := keys[0]
	config, ok := u.services.Oauth(serviceName)
	if !ok {
		http.Error(w, "unsupported service", http.StatusBadRequest)
		return
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "unable generate state", http.StatusInternalServerError)
		return
	}

	state := hex.EncodeToString(b)
	u.services.AddState(state, serviceName)
	url := config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback is an external services callback handler.
func (u *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	email, err := u.getUserInfo(r.Context(), r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		fmt.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	strToken, hashedEmail, err := u.getBearerToken(r.Context(), email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Authorization", "Bearer "+strToken)

	http.SetCookie(w, &http.Cookie{
		Name:   "Bearer",
		Value:  strToken,
		MaxAge: 600,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   "X-Attribute-Email",
		Value:  hashedEmail,
		MaxAge: 600,
	})

	http.Redirect(w, r, u.config.RedirectURL, http.StatusTemporaryRedirect)
}

func (u *Authenticator) getUserInfo(ctx context.Context, state, code string) (string, error) {
	service, err := u.services.RemoveState(state)
	if err != nil {
		return "", err
	}
	oauth, ok := u.services.Oauth(service)
	if !ok {
		return "", fmt.Errorf("invalid oauth service")
	}

	token, err := oauth.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("code exchange failed: %s", err.Error())
	}

	email, err := oauth.GetUserEmail(ctx, token)
	if err != nil {
		return "", err
	}

	return email, nil
}

func (u *Authenticator) getBearerToken(ctx context.Context, email string) (string, string, error) {
	conn, sToken, err := u.plant.ConnectionArtifacts()
	if err != nil {
		return "", "", err
	}

	info, err := conn.NetworkInfo(ctx, client.WithSession(sToken))
	if err != nil {
		return "", "", err
	}

	return u.generator.NewBearer(email, info.CurrentEpoch())
}
