package geoip

import (
	"log/slog"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// ASNInfo holds the autonomous-system attributes resolved for an IP.
type ASNInfo struct {
	ASN          uint   // e.g. 16509 for Amazon
	Organization string // e.g. "Amazon.com, Inc."
}

// ASNReader wraps a GeoLite2-ASN .mmdb database. Concurrent-safe.
// When no database is configured, Lookup returns an empty ASNInfo.
type ASNReader struct {
	db *geoip2.Reader
}

// NewASNReader opens the ASN .mmdb file at path. Returns a no-op reader
// (not an error) when path is empty.
func NewASNReader(path string) (*ASNReader, error) {
	if path == "" {
		return &ASNReader{}, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	slog.Info("GeoIP ASN database loaded", "path", path, "type", db.Metadata().DatabaseType)
	return &ASNReader{db: db}, nil
}

// Lookup resolves ASN metadata for the given IP. Returns zero-valued ASNInfo
// when the database is missing or the IP is unknown.
func (r *ASNReader) Lookup(ip string) ASNInfo {
	if r.db == nil {
		return ASNInfo{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ASNInfo{}
	}
	rec, err := r.db.ASN(parsed)
	if err != nil {
		return ASNInfo{}
	}
	return ASNInfo{
		ASN:          rec.AutonomousSystemNumber,
		Organization: rec.AutonomousSystemOrganization,
	}
}

// Available reports whether a real database is loaded.
func (r *ASNReader) Available() bool { return r.db != nil }

// Close releases the database file handle.
func (r *ASNReader) Close() {
	if r.db != nil {
		_ = r.db.Close()
	}
}
