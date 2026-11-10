package admission

// This is the fork's explicit closed vocabulary extension. These codes are
// public classifications, never received strings or RPC error text.
func validCG1Reason(s string) bool {
	switch s {
	case "live", "no_grant", "not_yet", "expired", "seal_spent",
		"landlord_rotated", "landlord_changed", "identity_pending", "grant_pending",
		"binding_mismatch", "invalid_presentation", "oversize", "invalid_peer",
		"verifier_unavailable", "state_unavailable", "clock_invalid", "cancelled",
		"busy", "check_failed":
		return true
	}
	return false
}
