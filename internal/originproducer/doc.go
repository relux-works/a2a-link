// Package originproducer is the downstream run-origin producer. It implements
// runorigin.Producer and runorigin.Session on top of the existing cg1 Matrix
// admission path and offers the single construction point for the origin
// endpoint.
//
// Every identity fact comes from one protected host mapping file. The launcher
// supplies a retained-event reference and an input principal, never identity,
// policy, registration or event bytes. Each preparation owns its checker and
// its state scope. Only a Live verdict produces a Result.
//
// The package writes no log and its errors carry only a closed reason name.
package originproducer
