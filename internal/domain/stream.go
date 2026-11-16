package domain

import "github.com/google/uuid"

// StreamFor is a tenant's audit stream id. Every component that appends to
// a tenant's audit trail outside an action (policy changes) uses it, so
// those events chain and seal with the tenant's action events.
func StreamFor(tenantID uuid.UUID) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("actiongate-stream:"+tenantID.String()))
}
