// Package timerlint holds a source-level guard, not runtime code.
//
// Go 1.27 removed the asynctimerchan GODEBUG escape hatch, so a timer channel
// is unbuffered and a time.After whose channel is never received keeps a
// runtime timer armed for the full duration. One such timer is harmless; one
// per iteration of a retry, poll, or lease loop is a leak that grows with how
// long the failure lasts.
//
// The rule this package enforces is therefore narrow and mechanical: no
// time.After inside a for or range body. Single-shot waits outside a loop are
// fine and are deliberately not flagged. In a loop, use the cancellable
// eventRouter.SleepCtx helper, or own a *time.Timer and stop it on every exit
// path.
//
// The check itself lives in timerlint_test.go so it runs under `go test ./...`
// — and therefore inside `make qa` — with no extra tooling to install.
package timerlint
