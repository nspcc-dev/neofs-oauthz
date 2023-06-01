package bearer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	neofsecdsa "github.com/nspcc-dev/neofs-sdk-go/crypto/ecdsa"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/user"
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
	EmailAttr   string
	Key         *keys.PrivateKey
	UserID      *user.ID
	ContainerID cid.ID
	LifeTime    uint64
}

// NewBearer generates new token for supplied email.
func (b *Generator) NewBearer(email string, currentEpoch uint64) (string, string, error) {
	hashedEmail := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))

	t := eacl.CreateTable(b.config.ContainerID)
	// order of rec is important
	rec := eacl.CreateRecord(eacl.ActionAllow, eacl.OperationPut)
	rec.AddObjectAttributeFilter(eacl.MatchStringEqual, b.config.EmailAttr, hashedEmail)
	eacl.AddFormedTarget(rec, eacl.RoleOthers)
	t.AddRecord(rec)
	rec2 := eacl.CreateRecord(eacl.ActionDeny, eacl.OperationPut)
	eacl.AddFormedTarget(rec2, eacl.RoleOthers)
	t.AddRecord(rec2)

	var bt bearer.Token
	bt.SetEACLTable(*t)
	if b.config.UserID != nil {
		bt.ForUser(*b.config.UserID)
	}
	bt.SetExp(currentEpoch + b.config.LifeTime)

	if err := bt.Sign(neofsecdsa.SignerRFC6979(b.config.Key.PrivateKey)); err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(bt.Marshal()), hashedEmail, nil
}
