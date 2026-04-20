package firewall

import (
	"path/filepath"
	"testing"
)

func newTestShield(t *testing.T) *ShieldService {
	t.Helper()
	dir := t.TempDir()
	return NewShieldService(
		filepath.Join(dir, "middleware.yaml"),
		filepath.Join(dir, "state.json"),
		"http://janus:9090",
	)
}

func TestBlockUnblock(t *testing.T) {
	s := newTestShield(t)
	if err := s.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !s.IsBlocked("1.2.3.4") {
		t.Fatal("expected blocked")
	}
	if err := s.UnblockIP("1.2.3.4"); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if s.IsBlocked("1.2.3.4") {
		t.Fatal("expected unblocked")
	}
}

func TestBlockIdempotent(t *testing.T) {
	s := newTestShield(t)
	_ = s.BlockIP("9.9.9.9")
	_ = s.BlockIP("9.9.9.9")
	if got := s.ListBlocked(); len(got) != 1 {
		t.Fatalf("want 1 blocked, got %d", len(got))
	}
}

func TestBlockRejectsInvalid(t *testing.T) {
	s := newTestShield(t)
	if err := s.BlockIP("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestImmunityPreventsBlock(t *testing.T) {
	s := newTestShield(t).WithImmunity(func(ip string) bool { return ip == "10.0.0.1" })
	if err := s.BlockIP("10.0.0.1"); err == nil {
		t.Fatal("expected immunity to reject block")
	}
	if s.IsBlocked("10.0.0.1") {
		t.Fatal("immune IP should not be blocked")
	}
}

func TestImmunityOverridesExistingBlock(t *testing.T) {
	// Block first, then add immunity — IsBlocked must return false so hot path doesn't lock out.
	s := newTestShield(t)
	_ = s.BlockIP("10.0.0.2")
	s.WithImmunity(func(ip string) bool { return ip == "10.0.0.2" })
	if s.IsBlocked("10.0.0.2") {
		t.Fatal("newly-immune IP must be treated as unblocked on hot path")
	}
}

func TestAdminWhitelistAddRemove(t *testing.T) {
	s := newTestShield(t)
	if err := s.AddAdminIP("192.168.1.10"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := s.GetAdminWhitelist(); len(got) != 1 || got[0] != "192.168.1.10" {
		t.Fatalf("whitelist: %v", got)
	}
	if err := s.RemoveAdminIP("192.168.1.10"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := s.GetAdminWhitelist(); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestStatePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	mw := filepath.Join(dir, "mw.yaml")
	st := filepath.Join(dir, "st.json")

	s1 := NewShieldService(mw, st, "http://janus:9090")
	_ = s1.BlockIP("5.5.5.5")
	_ = s1.AddAdminIP("6.6.6.6")

	s2 := NewShieldService(mw, st, "http://janus:9090")
	if !s2.IsBlocked("5.5.5.5") {
		t.Fatal("blocked IP not persisted")
	}
	if got := s2.GetAdminWhitelist(); len(got) != 1 || got[0] != "6.6.6.6" {
		t.Fatalf("admin whitelist not persisted: %v", got)
	}
}
