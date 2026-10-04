package engine

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, p string) []byte {
	b, err := os.ReadFile("../../" + p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidateAndSimulate(t *testing.T) {
	bundle := fixture(t, "tests/fixtures/bundle-example.json")
	if _, err := Validate(bundle); err != nil {
		t.Fatal(err)
	}
	ctx := []byte(`{"user":{"id":"u"},"channel":"web_upload","destination":{"external":true}}`)
	out, err := Simulate(bundle, ctx, fixture(t, "tests/corpus/positive/card-export-12.csv"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Verdict struct{ Action string } `json:"verdict"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.Verdict.Action != "block" {
		t.Fatalf("got %s / %v", out, err)
	}
}

func TestErrorsAreStructured(t *testing.T) {
	_, err := Validate([]byte(`{"nope":1}`))
	var e *Error
	if !errors.As(err, &e) || e.Code != "invalid_bundle" {
		t.Fatalf("got %v", err)
	}
	_, err = Validate([]byte("{\x00}"))
	if !errors.As(err, &e) || e.Code != "invalid_input" {
		t.Fatalf("NUL not rejected: %v", err)
	}
}

func TestConcurrentCallsAreSafe(t *testing.T) {
	bundle := fixture(t, "tests/fixtures/bundle-example.json")
	content := fixture(t, "tests/corpus/positive/card-export-12.csv")
	ctx := []byte(`{"user":{"id":"u"},"channel":"web_upload","destination":{"external":true}}`)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Simulate(bundle, ctx, content, time.Now()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
