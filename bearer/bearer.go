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

type newRecordFun func() eacl.Record

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
		func() eacl.Record {
			rec := eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationPut, []eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)})
			rec.SetFilters([]eacl.Filter{eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchNotPresent, "")})

			return rec
		},
		func() eacl.Record {
			epochs := uint64(b.config.ObjectMaxLifetime.Milliseconds() / msPerEpoch)
			maxExpirationEpoch := strconv.FormatUint(currentEpoch+b.config.LifeTime+epochs, 10)

			// order of rec is important
			rec := eacl.ConstructRecord(eacl.ActionAllow, eacl.OperationPut, []eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)})
			filters := []eacl.Filter{
				eacl.NewObjectPropertyFilter(b.config.EmailAttr, eacl.MatchStringEqual, hashedEmail),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "application/javascript"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "application/x-javascript"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "text/javascript"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "application/xhtml+xml"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "text/html"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, "text/htmlh"),
				eacl.NewObjectPropertyFilter(object.AttributeContentType, eacl.MatchStringNotEqual, ""),
				eacl.NewFilterObjectPayloadSizeIs(eacl.MatchNumLE, b.config.MaxObjectSize),
				eacl.NewObjectPropertyFilter(object.AttributeExpirationEpoch, eacl.MatchNumLE, maxExpirationEpoch),
			}
			rec.SetFilters(filters)

			return rec
		},
		func() eacl.Record {
			return eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationPut, []eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)})
		},
	}

	return records
}

// NewBearer generates new token for supplied email.
func (b *Generator) NewBearer(email string, currentEpoch uint64, msPerEpoch int64) (string, string, error) {
	var (
		hashedEmail = fmt.Sprintf("%x", sha256.Sum256([]byte(email)))
		records     = b.createRecords(hashedEmail, currentEpoch, msPerEpoch)
		eaclRecords = make([]eacl.Record, 0, len(records))
	)

	for _, record := range records {
		eaclRecords = append(eaclRecords, record())
	}

	t := eacl.ConstructTable(eaclRecords)
	t.SetCID(b.config.ContainerID)

	var bt bearer.Token
	bt.SetEACLTable(t)
	if b.config.UserID != nil {
		bt.ForUser(*b.config.UserID)
	}
	bt.SetExp(currentEpoch + b.config.LifeTime)

	if err := bt.Sign(user.NewAutoIDSignerRFC6979(b.config.Key.PrivateKey)); err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(bt.Marshal()), hashedEmail, nil
}
