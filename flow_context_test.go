package proxify

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// TestFlowContextAccessors pins the constructor-to-accessor contract: the
// exported getters return exactly what newFlowContext was handed.
func TestFlowContextAccessors(t *testing.T) {
	f := newFlowContext("flow-1", "conn-1", true)
	if got := f.ID(); got != "flow-1" {
		t.Errorf("ID() = %q, want %q", got, "flow-1")
	}
	if got := f.ConnectionID(); got != "conn-1" {
		t.Errorf("ConnectionID() = %q, want %q", got, "conn-1")
	}
	if !f.IsSecure() {
		t.Error("IsSecure() = false, want true")
	}
}

// TestFlowContextGetSet covers presence/absence semantics of the value map.
func TestFlowContextGetSet(t *testing.T) {
	f := newFlowContext("flow-1", "conn-1", false)

	if _, ok := f.Get("missing"); ok {
		t.Error("Get(missing) reported present, want absent")
	}

	f.Set("k", "v")
	val, ok := f.Get("k")
	if !ok {
		t.Fatal("Get(k) reported absent after Set")
	}
	if val != "v" {
		t.Errorf("Get(k) = %v, want %q", val, "v")
	}
}

// TestFlowContextEmptyIDFallback verifies the google/uuid fallback fires only
// when no id is supplied and produces a parseable UUID.
func TestFlowContextEmptyIDFallback(t *testing.T) {
	f := newFlowContext("", "", false)
	if f.ID() == "" {
		t.Fatal("ID() is empty; expected uuid fallback")
	}
	if _, err := uuid.Parse(f.ID()); err != nil {
		t.Fatalf("fallback ID %q is not a valid uuid: %v", f.ID(), err)
	}

	// A non-empty id must be preserved verbatim (no fallback).
	if got := newFlowContext("explicit", "", false).ID(); got != "explicit" {
		t.Errorf("ID() = %q, want %q (no fallback when id given)", got, "explicit")
	}
}

// TestFlowContextConcurrentSetGet drives 100 goroutines writing and reading
// unique keys so `go test -race` proves the RWMutex actually guards the map.
func TestFlowContextConcurrentSetGet(t *testing.T) {
	f := newFlowContext("flow-1", "conn-1", false)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			f.Set(key, i)
			if got, ok := f.Get(key); !ok || got != i {
				t.Errorf("Get(%q) = %v, %v; want %d, true", key, got, ok, i)
			}
		}(i)
	}
	wg.Wait()

	// All 100 keys survived the concurrent writes.
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("key-%d", i)
		if got, ok := f.Get(key); !ok || got != i {
			t.Errorf("after wait Get(%q) = %v, %v; want %d, true", key, got, ok, i)
		}
	}
}
