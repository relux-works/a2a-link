package main

import "path/filepath"

// Controls overlay the selected dependency without editing its module cache.
// Every plant is checked against its named genuine-Core adapter witness.
func policyPlants(module string) []plant {
	checker := filepath.Join(module, "checker.go")
	fresh := filepath.Join(module, "freshness.go")
	provision := filepath.Join(module, "provision.go")
	return []plant{
		{"executor-pin", "canonical grant terms must match the consumer executor", "./internal/cg1", "TestCoreMatrixPolicy/ExecutorPin", "Reason:allowed", []edit{{checker, `if pay.ExecutorKey != c.config.ExecutorKey {`, `if false && pay.ExecutorKey != c.config.ExecutorKey {`, 1}}},
		{"headers-ahead", "headers must equal blocks on the consumed Core observation", "./internal/cg1", "TestCoreMatrixPolicy/HeadersAhead", "Reason:allowed", []edit{{fresh, `if info.IBD || info.Headers != info.Blocks {`, `if info.IBD {`, 1}}},
		{"frozen-floor", "a complete frozen view below the trusted floor cannot be admitted", "./internal/cg1", "TestCoreMatrixPolicy/FrozenOldView", "Reason:allowed", []edit{{fresh, `if info.Blocks < *n.policy.MinimumHeight {`, `if false && info.Blocks < *n.policy.MinimumHeight {`, 1}}},
		{"frozen-age", "the recorded Core view is refused at A+1 second", "./internal/cg1", "TestCoreMatrixPolicy/AgeBoundary", "Reason:live", []edit{{fresh, `if n.tipTime.Before(now.Add(-n.policy.MaxTipAge)) {`, `if false && n.tipTime.Before(now.Add(-n.policy.MaxTipAge)) {`, 1}}},
		{"future-tip", "a real Core tip two hours ahead cannot evade configured F", "./internal/cg1", "TestCoreMatrixPolicy/FutureTip", "Reason:allowed", []edit{{fresh, `if n.tipTime.After(now.Add(*n.policy.MaxFutureSkew)) {`, `if false && n.tipTime.After(now.Add(*n.policy.MaxFutureSkew)) {`, 1}}},
		{"provision-cache-refusal", "refused spent proofs cannot populate or replace the proof cache", "./internal/cg1", "TestCoreMatrixPolicy/Provisioning/Spent", "refusal populated cold cache", []edit{{checker, `if out.Decision == Live && supplied != nil {`, `if supplied != nil {`, 1}}},
		{"provision-audit", "valid protected provisioning must leave its durable audit record", "./internal/cg1", "TestCoreMatrixPolicy/Provisioning/Tampered", "missing provision audit", []edit{{provision, `func appendProvision(m *state, p Presentation, v Verdict, at int64) {`, `func appendProvision(m *state, p Presentation, v Verdict, at int64) { return`, 1}}},
	}
}
