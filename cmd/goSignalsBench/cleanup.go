package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// victim is one stream the harness must delete, on the node that owns it.
type victim struct {
	n  *node
	id string
}

// victims lists every stream in the topology in deletion order. Receivers go
// first so no transmitter is left pointing at a deleted peer; for SSTP the
// initiator half goes before the responder it dials; ingress goes last.
func (t *topology) victims(gs1, gs2 *node) []victim {
	sstpInit, sstpResp := victim{gs1, pairOf(t.sstp1)}, victim{gs2, pairOf(t.sstp2)}
	if t.sstp1 != nil && t.sstp1.SstpMethod != nil && t.sstp1.SstpMethod.Role == model.SstpRoleResponder {
		sstpInit, sstpResp = sstpResp, sstpInit
	}
	all := []victim{{gs2, idOf(t.rxPoll)}, {gs1, idOf(t.txPoll)}, {gs1, idOf(t.txPush)}, {gs2, idOf(t.rxPush)}, sstpInit, sstpResp, {gs1, idOf(t.ingress)}}
	out := make([]victim, 0, len(all))
	for _, v := range all {
		if v.id != "" {
			out = append(out, v)
		}
	}
	return out
}

func deleteVictims(victims []victim) {
	for _, v := range victims {
		if err := v.n.deleteStream(v.id); err != nil {
			logf("warning: delete stream %s on %s: %v", v.id, v.n.name, err)
		}
	}
}

// inFlightFile records the streams of a run that has not finished yet, so a
// run that dies without reaching teardown (kill -9, laptop sleep, a crash in
// the harness) leaves a note the next run acts on. Leftover streams are not
// harmless: they still match the same audiences, so every SET reaches
// goSignals2 twice, once through the orphan and once through the new stream,
// and whichever arrives second is dropped by JTI dedup and never counted on
// the stream the harness is watching. The result is a run that stalls short
// of 100% on every leg. Each stream is deleted with the token of the client
// that created it, which is why the tokens are kept here; the file lives
// under the (git-ignored) output directory and is removed on a clean finish.
type inFlightFile struct {
	Created time.Time               `json:"created"`
	Nodes   map[string]inFlightNode `json:"nodes"`
	Streams []inFlightStream        `json:"streams"`
}

type inFlightNode struct {
	HostBase string `json:"host_base"`
	Token    string `json:"token"`
}

type inFlightStream struct {
	Node string `json:"node"`
	Id   string `json:"id"`
}

func inFlightPath(o *options) string {
	return filepath.Join(o.outDir, "streams-in-flight.json")
}

func recordInFlight(o *options, victims []victim) {
	f := inFlightFile{Created: time.Now().UTC(), Nodes: map[string]inFlightNode{}}
	for _, v := range victims {
		f.Nodes[v.n.name] = inFlightNode{HostBase: v.n.hostBase, Token: v.n.token}
		f.Streams = append(f.Streams, inFlightStream{Node: v.n.name, Id: v.id})
	}
	if err := os.MkdirAll(o.outDir, 0o755); err != nil {
		logf("warning: cannot record in-flight streams: %v", err)
		return
	}
	data, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(inFlightPath(o), data, 0o600); err != nil {
		logf("warning: cannot record in-flight streams: %v", err)
	}
}

func clearInFlight(o *options) {
	if err := os.Remove(inFlightPath(o)); err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("warning: cannot remove %s: %v", inFlightPath(o), err)
	}
}

// removeOrphans deletes the streams a previous, unfinished run left behind.
// It runs before the new topology is built so the orphans are gone before the
// first SET is pushed. The stack may have been wiped since (make dev-clean),
// in which case every delete fails with 401/404 and the note is dropped.
func removeOrphans(o *options, gs1, gs2 *node) {
	data, err := os.ReadFile(inFlightPath(o))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		logf("warning: cannot read %s: %v", inFlightPath(o), err)
		return
	}
	var f inFlightFile
	if err := json.Unmarshal(data, &f); err != nil {
		logf("warning: ignoring unreadable %s: %v", inFlightPath(o), err)
		clearInFlight(o)
		return
	}
	logf("removing %d streams left by the run started %s", len(f.Streams), f.Created.Format(time.RFC3339))
	nodes := map[string]*node{}
	for name, n := range f.Nodes {
		// Deletes go to the node's current host base, with the token of the
		// client that created the stream.
		base := n.HostBase
		switch name {
		case gs1.name:
			base = gs1.hostBase
		case gs2.name:
			base = gs2.hostBase
		}
		nodes[name] = &node{name: name, hostBase: base, token: n.Token, http: gs1.http}
	}
	victims := make([]victim, 0, len(f.Streams))
	for _, s := range f.Streams {
		if n := nodes[s.Node]; n != nil {
			victims = append(victims, victim{n, s.Id})
		}
	}
	deleteVictims(victims)
	clearInFlight(o)
}

// onInterrupt tears the topology down when the harness is interrupted, then
// exits with the conventional 128+SIGINT status. Returns the stop function
// the caller runs once the normal teardown path has taken over.
func onInterrupt(cleanup func()) func() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s, ok := <-sig
		if !ok {
			return
		}
		logf("%s received, removing benchmark streams", s)
		cleanup()
		os.Exit(130)
	}()
	return func() {
		signal.Stop(sig)
		close(sig)
	}
}
