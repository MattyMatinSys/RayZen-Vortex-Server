package udpserver

import (
	"testing"
	"time"
)

func TestStaleSessionCloseDoesNotRemoveReusedID(t *testing.T) {
	store := newSessionStore(8, 32)
	payload := make([]byte, sessionInitDataSize)
	payload[6] = 1
	old, _, err := store.findOrCreate(payload, 0, 0, 1, nil)
	if err != nil || old == nil {
		t.Fatalf("create old session: %v", err)
	}
	old.Cookie = 1
	lookup, _ := store.Lookup(old.ID)

	// A worker has already checked the old close's cookie. The cleanup
	// worker removes that session and another SESSION_INIT reuses its ID
	// before the original worker gets the exclusive close lock.
	now := time.Now().Add(time.Hour)
	if expired := store.Cleanup(now, time.Minute, time.Minute); len(expired) != 1 {
		t.Fatalf("expired sessions = %d, want 1", len(expired))
	}
	store.nextID = uint16(old.ID)
	payload[6] = 2
	current, _, err := store.findOrCreate(payload, 0, 0, 1, nil)
	if err != nil || current == nil || current.ID != old.ID {
		t.Fatalf("reuse old ID: session=%v err=%v", current, err)
	}
	current.Cookie = 2
	if record, closed := store.Close(old.ID, lookup.Cookie, now, time.Minute); closed || record != nil {
		t.Fatal("stale close removed the new session")
	}
	if got, active := store.Get(current.ID); !active || got != current || current.isClosed() || store.activeCount != 1 {
		t.Fatal("new session did not remain active after stale close")
	}
	if store.bySig[current.Signature] != current.ID {
		t.Fatal("stale close removed the new session's retry signature")
	}
	if record, closed := store.Close(current.ID, current.Cookie, now, time.Minute); !closed || record != current {
		t.Fatal("valid close did not remove the matching session")
	}
	if store.activeCount != 0 || !current.isClosed() {
		t.Fatal("valid close did not update session lifecycle")
	}
}
