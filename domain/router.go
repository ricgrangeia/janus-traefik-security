package domain

// Router is an entity representing a Traefik router and its observed state.
// It is identified by its Name — two routers with the same name are the same entity.
type Router struct {
	Name        string
	Rule        string
	Provider    string
	Entrypoints []string
	Middlewares []string // middleware reference names, resolved via NetworkSnapshot
	HasTLS      bool
	IsHTTPS     bool   // set by the infrastructure mapper based on entrypoint type
	IsRedirect  bool   // true when the router's sole purpose is HTTP→HTTPS redirection
	Status      string
}

// ID returns the unique identifier of this router entity.
func (r Router) ID() string {
	return r.Name
}

// RequiresTLSAudit returns true when TLS compliance should be enforced.
// Only routers bound to a secure (HTTPS) entrypoint are expected to have TLS.
func (r Router) RequiresTLSAudit() bool {
	return r.IsHTTPS
}
