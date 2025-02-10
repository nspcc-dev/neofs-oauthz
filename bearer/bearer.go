package bearer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

// Generator is bearer token generator.
type Generator struct {
	config *Config
}

type newRecordFun func() *eacl.Record

// NewGenerator creates new bearer token generator using config.
func NewGenerator(config *Config) *Generator {
	return &Generator{config: config}
}

// Config for bearer token generator.
type Config struct {
	EmailAttr         string
	Key               *keys.PrivateKey
	UserID            *user.ID
	ContainerID       cid.ID
	LifeTime          uint64
	MaxObjectSize     uint64
	ObjectMaxLifetime time.Duration
}

func (b *Generator) createRecords(hashedEmail string, currentEpoch uint64, msPerEpoch int64) []newRecordFun {
	records := []newRecordFun{
		func() *eacl.Record {
			rec := eacl.CreateRecord(eacl.ActionDeny, eacl.OperationPut)
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchNotPresent, object.AttributeContentType, "")

			return rec
		},
		func() *eacl.Record {
			epochs := uint64(b.config.ObjectMaxLifetime.Milliseconds() / msPerEpoch)
			maxExpirationEpoch := strconv.FormatUint(currentEpoch+b.config.LifeTime+epochs, 10)

			// order of rec is important
			rec := eacl.CreateRecord(eacl.ActionAllow, eacl.OperationPut)
			rec.AddObjectAttributeFilter(eacl.MatchStringEqual, b.config.EmailAttr, hashedEmail)
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "application/javascript")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "application/x-javascript")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "text/javascript")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "application/xhtml+xml")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "text/html")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "text/htmlh")
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchStringNotEqual, object.AttributeContentType, "")
			rec.AddObjectPayloadLengthFilter(eacl.MatchNumLE, b.config.MaxObjectSize)
			rec.AddFilter(eacl.HeaderFromObject, eacl.MatchNumLE, object.AttributeExpirationEpoch, maxExpirationEpoch)

			return rec
		},
		func() *eacl.Record {
			rec := eacl.CreateRecord(eacl.ActionDeny, eacl.OperationPut)
			eacl.AddFormedTarget(rec, eacl.RoleOthers)

			return rec
		},
	}

	return records
}

// NewBearer generates new token for supplied email.
func (b *Generator) NewBearer(email string, currentEpoch uint64, msPerEpoch int64) (string, string, error) {
	hashedEmail := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))

	records := b.createRecords(hashedEmail, currentEpoch, msPerEpoch)
	t := eacl.CreateTable(b.config.ContainerID)

	for _, record := range records {
		rec := record()
		eacl.AddFormedTarget(rec, eacl.RoleOthers)
		t.AddRecord(rec)
	}

	var bt bearer.Token
	bt.SetEACLTable(*t)
	if b.config.UserID != nil {
		bt.ForUser(*b.config.UserID)
	}
	bt.SetExp(currentEpoch + b.config.LifeTime)

	if err := bt.Sign(user.NewAutoIDSignerRFC6979(b.config.Key.PrivateKey)); err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(bt.Marshal()), hashedEmail, nil
}
