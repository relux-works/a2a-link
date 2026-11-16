package cli

// The 26 r4 codes are closed; no raw dependency error is public evidence.
type vaultCode string

const (
	vaultEVersion              vaultCode = "E_VERSION"
	vaultEFormat               vaultCode = "E_FORMAT"
	vaultELimit                vaultCode = "E_LIMIT"
	vaultEIdentity             vaultCode = "E_IDENTITY"
	vaultEContext              vaultCode = "E_CONTEXT"
	vaultEIdentityConflict     vaultCode = "E_IDENTITY_CONFLICT"
	vaultEHome                 vaultCode = "E_HOME"
	vaultEBackendConfig        vaultCode = "E_BACKEND_CONFIG"
	vaultEUnavailable          vaultCode = "E_UNAVAILABLE"
	vaultEServerUntrusted      vaultCode = "E_SERVER_UNTRUSTED"
	vaultECallerUntrusted      vaultCode = "E_CALLER_UNTRUSTED"
	vaultEOperationDenied      vaultCode = "E_OPERATION_DENIED"
	vaultEReplay               vaultCode = "E_REPLAY"
	vaultEUnknownIdentity      vaultCode = "E_UNKNOWN_IDENTITY"
	vaultERevoked              vaultCode = "E_REVOKED"
	vaultEDeleted              vaultCode = "E_DELETED"
	vaultEConflict             vaultCode = "E_CONFLICT"
	vaultESessionRequired      vaultCode = "E_SESSION_REQUIRED"
	vaultESessionStale         vaultCode = "E_SESSION_STALE"
	vaultESessionBinding       vaultCode = "E_SESSION_BINDING"
	vaultECustody              vaultCode = "E_CUSTODY"
	vaultEIntegrity            vaultCode = "E_INTEGRITY"
	vaultEAudit                vaultCode = "E_AUDIT"
	vaultEMigrationUnqualified vaultCode = "E_MIGRATION_UNQUALIFIED"
	vaultEMigrationConflict    vaultCode = "E_MIGRATION_CONFLICT"
	vaultEInternal             vaultCode = "E_INTERNAL"
)

var vaultAllCodes = [...]vaultCode{vaultEVersion, vaultEFormat, vaultELimit, vaultEIdentity, vaultEContext, vaultEIdentityConflict, vaultEHome, vaultEBackendConfig, vaultEUnavailable, vaultEServerUntrusted, vaultECallerUntrusted, vaultEOperationDenied, vaultEReplay, vaultEUnknownIdentity, vaultERevoked, vaultEDeleted, vaultEConflict, vaultESessionRequired, vaultESessionStale, vaultESessionBinding, vaultECustody, vaultEIntegrity, vaultEAudit, vaultEMigrationUnqualified, vaultEMigrationConflict, vaultEInternal}

func (c vaultCode) Known() bool {
	for _, v := range vaultAllCodes {
		if c == v {
			return true
		}
	}
	return false
}

type vaultOutcome string

const (
	vaultNotSubmitted vaultOutcome = "NOT_SUBMITTED"
	vaultRefused      vaultOutcome = "REFUSED"
	vaultSucceeded    vaultOutcome = "SUCCEEDED"
	vaultUnknown      vaultOutcome = "UNKNOWN"
)

type vaultDiagnosis string

const (
	vaultDiagTransport  vaultDiagnosis = "transport_lost"
	vaultDiagMalformed  vaultDiagnosis = "reply_malformed"
	vaultDiagMismatch   vaultDiagnosis = "reply_mismatch"
	vaultDiagLimit      vaultDiagnosis = "reply_over_limit"
	vaultDiagInternal   vaultDiagnosis = "internal_after_invoke"
	vaultDiagSubmission vaultDiagnosis = "submission_unproven"
	vaultDiagPeer       vaultDiagnosis = "peer_recheck_failed"
)

type vaultStage string

const (
	vaultStageMetadata     vaultStage = "metadata"
	vaultStageAdmission    vaultStage = "admission"
	vaultStageDependency   vaultStage = "dependency"
	vaultStageOpen         vaultStage = "open"
	vaultStageVerification vaultStage = "verification"
	vaultStagePrepare      vaultStage = "prepare"
	vaultStageInvoke       vaultStage = "invoke"
	vaultStageReply        vaultStage = "reply"
	vaultStageHandoff      vaultStage = "handoff"
	vaultStageCleanup      vaultStage = "cleanup"
)

type vaultFailure struct {
	Outcome   vaultOutcome
	Code      vaultCode
	Diagnosis vaultDiagnosis
	Stage     vaultStage
	Op        vaultOp
}

func (r *vaultFailure) Error() string {
	return r.summary() + r.location()
}
func (r *vaultFailure) summary() string {
	if r == nil {
		return "vault-v1"
	}
	// Never render an unchecked field, payload, panic value or native error.
	state := r.Outcome
	switch state {
	case vaultNotSubmitted, vaultRefused:
		if r.Code.Known() {
			return "vault-v1 " + string(state) + " " + string(r.Code)
		}
	case vaultUnknown:
		switch r.Diagnosis {
		case vaultDiagTransport, vaultDiagMalformed, vaultDiagMismatch, vaultDiagLimit, vaultDiagInternal, vaultDiagSubmission, vaultDiagPeer:
			return "vault-v1 UNKNOWN " + string(r.Diagnosis)
		}
	}
	return "vault-v1 NOT_SUBMITTED E_INTERNAL"
}
func vaultLocalFailure(c vaultCode) *vaultFailure {
	if !c.Known() {
		c = vaultEInternal
	}
	return &vaultFailure{Outcome: vaultNotSubmitted, Code: c}
}
func vaultNotSubmittedRefusal(c vaultCode) *vaultFailure { return vaultLocalFailure(c) }
func vaultRefusedFailure(c vaultCode) *vaultFailure {
	return &vaultFailure{Outcome: vaultRefused, Code: c}
}
func vaultUnknownFailure(d vaultDiagnosis) *vaultFailure {
	return &vaultFailure{Outcome: vaultUnknown, Diagnosis: d}
}

type vaultInvocationPhase string

const (
	vaultNoInvocation vaultInvocationPhase = "NO_INVOCATION"
	vaultInvoked      vaultInvocationPhase = "INVOKED"
)

type vaultOperationReport struct {
	Op         vaultOp
	Outcome    vaultOutcome
	Code       vaultCode
	Diagnosis  vaultDiagnosis
	Stage      vaultStage
	Invocation vaultInvocationPhase
}
type vaultHandoffState string

const (
	vaultHandoffNotEntered vaultHandoffState = "not_entered"
	vaultHandoffEntered    vaultHandoffState = "entered"
	vaultHandoffReturned   vaultHandoffState = "returned"
	vaultHandoffFailed     vaultHandoffState = "failed"
	vaultHandoffPanicked   vaultHandoffState = "panicked"
)

type vaultDeliveryDiagnosis string

const (
	vaultDeliveryFailed    vaultDeliveryDiagnosis = "consumer_failed"
	vaultDeliveryPanicked  vaultDeliveryDiagnosis = "consumer_panicked"
	vaultDeliveryCancelled vaultDeliveryDiagnosis = "handoff_cancelled"
	vaultDeliverySelection vaultDeliveryDiagnosis = "selection_unavailable_after_success"
)

type vaultCleanupState string

const (
	vaultCleanupNotNeeded vaultCleanupState = "not_needed"
	vaultCleanupClosed    vaultCleanupState = "closed"
	vaultCleanupFailed    vaultCleanupState = "failed"
)

type vaultAttemptReport struct {
	Register, Release *vaultOperationReport
	Failure           *vaultFailure
	Revision          uint64
	Handoff           vaultHandoffState
	DeliveryDiagnosis vaultDeliveryDiagnosis
	Cleanup           vaultCleanupState
}

func (r vaultAttemptReport) acquisitionOK() bool {
	return r.Failure == nil && r.Release != nil && r.Release.Outcome == vaultSucceeded && r.Handoff == vaultHandoffReturned && r.Cleanup == vaultCleanupClosed
}
func (r vaultAttemptReport) diagnostic() error {
	if r.Failure != nil {
		return r.Failure
	}
	switch r.DeliveryDiagnosis {
	case vaultDeliveryFailed, vaultDeliveryPanicked, vaultDeliveryCancelled, vaultDeliverySelection:
		return vaultDeliveryError(r.DeliveryDiagnosis)
	}
	if r.Cleanup == vaultCleanupFailed {
		return vaultCleanupError{}
	}
	if !r.acquisitionOK() {
		return vaultLocalFailure(vaultEInternal)
	}
	return nil
}

type vaultDeliveryError vaultDeliveryDiagnosis

func (e vaultDeliveryError) Error() string {
	switch vaultDeliveryDiagnosis(e) {
	case vaultDeliveryFailed, vaultDeliveryPanicked, vaultDeliveryCancelled, vaultDeliverySelection:
		return "vault-v1 SUCCEEDED " + string(e)
	}
	return "vault-v1 SUCCEEDED consumer_failed"
}

type vaultCleanupError struct{}

func (vaultCleanupError) Error() string { return "vault-v1 cleanup_failed" }

// Only literal operation/stage labels are appended to fixed diagnostics.
func (r *vaultFailure) location() string {
	if r == nil {
		return ""
	}
	op := ""
	switch r.Op {
	case vaultOpRegister:
		op = " register"
	case vaultOpRelease:
		op = " release"
	case vaultOpCloseSession:
		op = " close_session"
	}
	stage := ""
	switch r.Stage {
	case vaultStageMetadata, vaultStageAdmission, vaultStageDependency, vaultStageOpen, vaultStageVerification, vaultStagePrepare, vaultStageInvoke, vaultStageReply, vaultStageHandoff, vaultStageCleanup:
		stage = " " + string(r.Stage)
	}
	return op + stage
}
