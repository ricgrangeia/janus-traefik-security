package app

import "testing"

func TestMatchesPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything@docker", true},
		{"admin-*", "admin-dashboard@docker", true},
		{"admin-*", "user-api@docker", false},
		{"*-api", "public-api@docker", true},
		{"*-api", "api-service@docker", false},
		{"*admin*", "my-admin-panel@docker", true},
		{"*admin*", "users@docker", false},
		{"exact-router", "exact-router@docker", true},
		{"exact-router", "other-router@docker", false},
		{"Admin-*", "admin-dashboard@docker", true}, // case-insensitive
	}
	for _, c := range cases {
		if got := matchesPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
