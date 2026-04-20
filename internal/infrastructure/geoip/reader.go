// Package geoip wraps an offline MaxMind GeoLite2 .mmdb database to enrich
// IP addresses with country and city metadata — zero latency, zero privacy risk.
package geoip

import (
	"log/slog"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// IPMetadata holds the geographic attributes resolved for a single IP address.
type IPMetadata struct {
	CountryCode string // ISO 3166-1 alpha-2, e.g. "US"; "--" when unknown
	CountryName string // e.g. "United States"
	City        string // e.g. "San Francisco"; empty for Country-only databases
	Continent   string // e.g. "North America"
}

// Reader wraps a GeoLite2 .mmdb database. All methods are safe for concurrent use.
// When no database is configured, Lookup returns an empty record gracefully.
type Reader struct {
	db *geoip2.Reader
}

// NewReader opens the .mmdb file at path. Returns a no-op reader (not an error)
// when path is empty, so callers do not need to handle the nil case.
func NewReader(path string) (*Reader, error) {
	if path == "" {
		return &Reader{}, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	slog.Info("GeoIP database loaded", "path", path, "type", db.Metadata().DatabaseType)
	return &Reader{db: db}, nil
}

// Lookup resolves geo metadata for the given IP string.
// Returns IPMetadata with CountryCode "--" if the IP is invalid or not in the database.
func (r *Reader) Lookup(ip string) IPMetadata {
	if r.db == nil {
		return IPMetadata{CountryCode: "--"}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return IPMetadata{CountryCode: "--"}
	}

	// GeoLite2-City database (preferred — includes city-level detail).
	if rec, err := r.db.City(parsed); err == nil {
		return IPMetadata{
			CountryCode: rec.Country.IsoCode,
			CountryName: rec.Country.Names["en"],
			City:        rec.City.Names["en"],
			Continent:   rec.Continent.Names["en"],
		}
	}

	// GeoLite2-Country database fallback.
	if rec, err := r.db.Country(parsed); err == nil {
		return IPMetadata{
			CountryCode: rec.Country.IsoCode,
			CountryName: rec.Country.Names["en"],
			Continent:   rec.Continent.Names["en"],
		}
	}

	return IPMetadata{CountryCode: "--"}
}

// Available reports whether a real database is loaded.
func (r *Reader) Available() bool { return r.db != nil }

// Close releases the database file handle.
func (r *Reader) Close() {
	if r.db != nil {
		_ = r.db.Close()
	}
}
