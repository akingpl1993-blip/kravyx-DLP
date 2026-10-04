// Package secret holds values that must never be logged, printed or serialised.
package secret

import (
	"crypto/subtle"
	"log/slog"
)

const redacted = "[redacted]"

// String is a secret string. Every rendering path returns "[redacted]".
type String struct{ v string }

func New(v string) String { return String{v: v} }

func (s String) Reveal() string             { return s.v }
func (s String) Len() int                   { return len(s.v) }
func (s String) IsZero() bool               { return s.v == "" }
func (String) String() string               { return redacted }
func (String) GoString() string             { return redacted }
func (String) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (String) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (String) LogValue() slog.Value         { return slog.StringValue(redacted) }

// Equal compares in constant time with respect to the content.
func (s String) Equal(other string) bool {
	return subtle.ConstantTimeCompare([]byte(s.v), []byte(other)) == 1
}
