package vortexsrv

import (
	"testing"
	"time"
)

func TestZoneForDefaultsAndOverrides(t *testing.T) {
	z := ZoneFor("T.Example.com.", Settings{}, 7)
	if z.Zone != "t.example.com" || z.NSHost != "ns.example.com" || z.Hostmaster != "hostmaster.example.com" || z.Serial != 7 {
		t.Fatalf("defaults %+v", z)
	}
	z = ZoneFor("t.example.com", Settings{NSHost: "dns1.other.net", Hostmaster: "admin.other.net"}, 1)
	if z.NSHost != "dns1.other.net" || z.Hostmaster != "admin.other.net" {
		t.Fatalf("overrides %+v", z)
	}
	// A two-label zone is its own parent.
	if z := ZoneFor("example.com", Settings{}, 1); z.NSHost != "ns.example.com" {
		t.Fatalf("apex zone %+v", z)
	}
}

func TestHoldMaxClampAndDefault(t *testing.T) {
	ms := func(v int) *int { return &v }
	cases := []struct {
		in   *int
		want time.Duration
	}{{nil, DefaultHoldMaxMs * time.Millisecond}, {ms(0), 0}, {ms(-5), 0}, {ms(250), 250 * time.Millisecond}, {ms(99999), 3 * time.Second}}
	for _, c := range cases {
		if got := (Settings{HoldMaxMs: c.in}).HoldMax(); got != c.want {
			t.Fatalf("HoldMax(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	off := false
	if (Settings{}).IsAuthoritative() != true || (Settings{Authoritative: &off}).IsAuthoritative() {
		t.Fatal("authoritative default must be on and switchable off")
	}
}

func TestKeyLength(t *testing.T) {
	for m, want := range map[int]int{3: 16, 4: 24, 5: 32, 2: 32, 1: 32} {
		if KeyLength(m) != want {
			t.Fatalf("KeyLength(%d)", m)
		}
	}
}
