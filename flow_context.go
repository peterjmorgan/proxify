package proxify

import (
	"sync"

	"github.com/google/uuid"
)

// FlowContext carries Proxify-owned, engine-neutral state for a single
// request/response transaction ("flow"). It replaces the previously exposed
// *martian.Context in the public callback API so library consumers no longer
// depend on the serving engine. A protocol adapter (or the Martian bridge)
// creates one FlowContext per flow via newFlowContext and shares the same
// pointer between the request and response callbacks.
type FlowContext struct {
	id           string
	connectionID string
	secure       bool

	mu   sync.RWMutex
	vals map[string]interface{}
}

// newFlowContext builds a FlowContext for a single flow. id identifies the
// flow and connectionID the underlying connection; adapters that cannot yet
// distinguish the two may pass the same value for both. secure reports whether
// the flow rode a TLS-terminated (MITM'd) connection. When id is empty a
// google/uuid value is generated as a fallback so every flow has a stable,
// non-empty identifier.
func newFlowContext(id, connectionID string, secure bool) *FlowContext {
	if id == "" {
		id = uuid.NewString()
	}
	return &FlowContext{
		id:           id,
		connectionID: connectionID,
		secure:       secure,
		vals:         make(map[string]interface{}),
	}
}

// ID returns the flow identifier.
func (f *FlowContext) ID() string {
	return f.id
}

// ConnectionID returns the identifier of the connection carrying this flow.
func (f *FlowContext) ConnectionID() string {
	return f.connectionID
}

// IsSecure reports whether the flow rode a TLS-terminated connection.
func (f *FlowContext) IsSecure() bool {
	return f.secure
}

// Get returns the value stored under key and whether it was present.
func (f *FlowContext) Get(key string) (interface{}, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	val, ok := f.vals[key]
	return val, ok
}

// Set associates val with key for the lifetime of the flow. It is safe for
// concurrent use.
func (f *FlowContext) Set(key string, val interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.vals[key] = val
}
