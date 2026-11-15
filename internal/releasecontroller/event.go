package releasecontroller

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/relux-works/a2a-swarm/internal/sharedrelease"
)

// EventGate checks what GitHub delivered, not a caller-provided tag-shaped
// string. Cryptographic annotated-tag admission remains a separate required gate.
func EventGate() error {
	return eventGate(os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_EVENT_NAME"), os.Getenv("GITHUB_REF"))
}
func eventGate(repository, event, ref string) error {
	if repository != sharedrelease.Repository || event != "push" || !strings.HasPrefix(ref, "refs/tags/") {
		return errors.New("shared-tag-event-required")
	}
	b := sharedrelease.Binding{Tag: strings.TrimPrefix(ref, "refs/tags/"), Commit: strings.Repeat("a", 40), TagObject: strings.Repeat("b", 40)}
	if b.Validate() != nil {
		return errors.New("shared-stable-tag-required")
	}
	return nil
}

// AdmitWorkflow is called before the reusable native job or any signing fields
// can enter a process. The retained hold has no dispatch/env bypass.
func AdmitWorkflow() error {
	if e := EventGate(); e != nil {
		return e
	}
	if !ProductionReady {
		return errors.New(Hold)
	}
	return newProduction(Request{}).Lease(context.Background())
}
