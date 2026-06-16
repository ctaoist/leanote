// Package oid wraps primitive.ObjectID so the zero value marshals to JSON as an
// empty string (""), matching the original mgo-based leanote backend. The
// frontend builds its notebook tree from ParentNotebookId and expects ""—not
// "000000000000000000000000"—for absent ids.
package oid

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type OID primitive.ObjectID

// New returns a fresh ObjectID.
func New() OID { return OID(primitive.NewObjectID()) }

// FromHex parses a 24-char hex string; "" yields the zero OID (not an error).
func FromHex(s string) (OID, error) {
	if s == "" {
		return OID{}, nil
	}
	o, err := primitive.ObjectIDFromHex(s)
	if err != nil {
		return OID{}, err
	}
	return OID(o), nil
}

// Parse is a lenient FromHex: returns (zero, false) on empty/invalid input.
func Parse(s string) (OID, bool) {
	o, err := FromHex(s)
	if err != nil || o.IsZero() {
		return OID{}, false
	}
	return o, true
}

func (o OID) ObjectID() primitive.ObjectID { return primitive.ObjectID(o) }

func (o OID) Hex() string {
	if o.IsZero() {
		return ""
	}
	return primitive.ObjectID(o).Hex()
}

func (o OID) IsZero() bool { return primitive.ObjectID(o).IsZero() }

func (o OID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + o.Hex() + `"`), nil
}

func (o *OID) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		*o = OID{}
		return nil
	}
	parsed, err := primitive.ObjectIDFromHex(s)
	if err != nil {
		return err
	}
	*o = OID(parsed)
	return nil
}

// MarshalBSONValue encodes as a real BSON ObjectId so existing documents and
// new writes stay compatible with the legacy data.
func (o OID) MarshalBSONValue() (bsontype.Type, []byte, error) {
	return bson.MarshalValue(primitive.ObjectID(o))
}

func (o *OID) UnmarshalBSONValue(t bsontype.Type, data []byte) error {
	var oid primitive.ObjectID
	if err := bson.UnmarshalValue(t, data, &oid); err != nil {
		// Tolerate null/missing/legacy-shaped values: leave as zero.
		return nil
	}
	*o = OID(oid)
	return nil
}
