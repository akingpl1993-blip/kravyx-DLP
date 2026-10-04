package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretNeverRenders(t *testing.T) {
	s := New("hunter2-super-secret-value")
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "token", s)
	j, _ := json.Marshal(map[string]any{"token": s})
	out := strings.Join([]string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), string(j), buf.String()}, "\n")
	if strings.Contains(out, "hunter2") {
		t.Fatalf("secret leaked:\n%s", out)
	}
	if !s.Equal("hunter2-super-secret-value") || s.Equal("nope") {
		t.Fatal("Equal broken")
	}
}
