package app

import "strings"

// ParseKnownMiddlewares splits a comma-separated list of middleware names into
// a slice, trimming whitespace and dropping empty entries.
func ParseKnownMiddlewares(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
