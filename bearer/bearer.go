package bearer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/nspcc-dev/neofs-api-go/pkg/acl/eacl"
	"github.com/nspcc-dev/neofs-api-go/pkg/container"
	"github.com/nspcc-dev/neofs-api-go/pkg/owner"
	"github.com/nspcc-dev/neofs-api-go/pkg/token"
	"github.com/nspcc-dev/neofs-api-go/v2/acl"
	"github.com/nspcc-dev/neofs-sdk-go/pkg/neofs"
)

// Generator is bearer token generator.
type Generator struct {
	config *Config
}

// NewGenerator creates new bearer token generator using config.
func NewGenerator(config *Config) *Generator {
	return &Generator{config: config}
}

// Config for bearer token generator.
type Config struct {
	Creds       neofs.Credentials
	OwnerID     *owner.ID
	ContainerID *container.ID
	LifeTime    uint64
}

// NewBearer generates new token for supplied email.
func (b *Generator) NewBearer(email string, currentEpoch uint64) (string, string, error) {
	hashedEmail := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))

	bt := token.NewBearerToken()
	bt.SetOwner(b.config.OwnerID)

	t := new(eacl.Table)
	t.SetCID(b.config.ContainerID)

	// order of rec is important
	rec := eacl.CreateRecord(eacl.ActionAllow, eacl.OperationPut)
	rec.AddObjectAttributeFilter(eacl.MatchStringEqual, "Email", hashedEmail)
	eacl.AddFormedTarget(rec, eacl.RoleOthers)
	t.AddRecord(rec)
	rec2 := eacl.CreateRecord(eacl.ActionDeny, eacl.OperationPut)
	eacl.AddFormedTarget(rec2, eacl.RoleOthers)
	t.AddRecord(rec2)

	bt.SetEACLTable(t)

	lt := new(acl.TokenLifetime)
	lt.SetExp(currentEpoch + b.config.LifeTime)
	bt.SetLifetime(lt.GetExp(), lt.GetNbf(), lt.GetIat())

	if err := bt.SignToken(b.config.Creds.PrivateKey()); err != nil {
		return "", "", err
	}

	raw, err := bt.Marshal()
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(raw), hashedEmail, nil
}
