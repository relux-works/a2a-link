package al3smoke

import "encoding/json"

// Normalize validates both full transcripts before removing run-specific keys,
// IDs and URLs. Equal normalized output is never a substitute for correlation.
func Normalize(aRows, bRows []Evidence, a, b, relayURL, runID string) ([]byte, error) {
	if !hexValue(a, 64) || !hexValue(b, 64) || a == b || !hexValue(runID, 16) {
		return nil, ErrSmoke
	}
	all := map[string][]Evidence{"a": aRows, "b": bRows}
	for _, role := range []string{"a", "b"} {
		rows := all[role]
		if len(rows) != 4 {
			return nil, ErrSmoke
		}
		self, peer := a, b
		sequence := []string{"ready", "sent", "received", "complete"}
		if role == "b" {
			self, peer = b, a
			sequence = []string{"ready", "received", "sent", "complete"}
		}
		for i, row := range rows {
			if row.Type != sequence[i] || row.Role != role || row.Pending != 0 {
				return nil, ErrSmoke
			}
			switch row.Type {
			case "ready":
				if row.Sender != self || row.Recipient != peer {
					return nil, ErrSmoke
				}
			case "sent", "received":
				from, to := self, peer
				if row.Type == "received" {
					from, to = peer, self
				}
				if row.Sender != from || row.Recipient != to || !hexValue(row.ID, 64) {
					return nil, ErrSmoke
				}
				if row.Type == "sent" {
					if len(row.Routes) != 2 {
						return nil, ErrSmoke
					}
					for _, key := range []string{self, peer} {
						urls := row.Routes[key]
						if len(urls) != 1 || urls[0] != relayURL {
							return nil, ErrSmoke
						}
					}
				}
			}
		}
	}
	if aRows[1].ID != bRows[1].ID || bRows[2].ID != aRows[2].ID || aRows[1].ID == bRows[2].ID {
		return nil, ErrSmoke
	}
	ping, pong := "al3:"+runID+":ping", "al3:"+runID+":pong"
	if aRows[1].Text != ping || bRows[1].Text != ping || bRows[2].Text != pong || aRows[2].Text != pong {
		return nil, ErrSmoke
	}
	return json.Marshal(struct {
		A, B             []string
		Route, Discovery string
		Pending          int
	}{[]string{"ready", "sent:ping", "received:pong", "complete"}, []string{"ready", "received:ping", "sent:pong", "complete"}, "observed-only", "empty-configured-fallback", 0})
}
