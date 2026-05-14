// Package logger wraps the standard library's log/slog with the project-wide
// initialization pattern, per-component sub-loggers, and a small set of
// well-known default attributes used to identify the running process.
//
// Output format:
//   - Default ("" or "text"): human-readable text via slog.TextHandler — kept
//     for `go run` / `go test` ergonomics.
//   - "json": one parseable JSON object per line via slog.JSONHandler — meant
//     for container deployment where an external collector (Alloy, Fluent Bit,
//     CloudWatch agent, etc.) ships logs to a backend.
//
// Default attribute conventions (set by main.go via Options.Attrs):
//
//	service       (e.g. "gosignals", "gossfserver")
//	version       (constants.GoSignalsVersion)
//	node_id       (pkg/nodeid.Resolve())
//	cluster_name  (env I2SIG_CLUSTER_NAME, omitted when empty)
//
// `component` is attached by Sub() at construction time.
//
// Reserved JSON field namespace: the prefix `op_event_*` is reserved for the
// planned Operational Security Event Tokens feature (v2). Do not introduce
// log-line keys in that namespace until that feature lands.
package logger

import (
    "context"
    "io"
    "log/slog"
    "os"
    "strings"
)

var (
    globalLevel = new(slog.LevelVar)
)

// Options configures the global slog logger.
type Options struct {
    // Level: "debug", "info", "warn"/"warning", "error". Empty/unrecognized → "info".
    Level string
    // Format: "json" enables slog.JSONHandler; anything else (including empty) uses slog.TextHandler.
    Format string
    // Attrs are attached as default attributes on every log record.
    Attrs []slog.Attr
    // Writer overrides the destination. Defaults to os.Stdout.
    Writer io.Writer
}

func init() {
    globalLevel.Set(slog.LevelInfo)
    slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: globalLevel})))
}

// Init configures the global slog logger.
func Init(o Options) {
    globalLevel.Set(parseLevel(o.Level))

    w := o.Writer
    if w == nil {
        w = os.Stdout
    }

    var handler slog.Handler
    if strings.EqualFold(o.Format, "json") {
        handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: globalLevel})
    } else {
        handler = slog.NewTextHandler(w, &slog.HandlerOptions{Level: globalLevel})
    }
    if len(o.Attrs) > 0 {
        handler = handler.WithAttrs(o.Attrs)
    }
    slog.SetDefault(slog.New(handler))
}

func parseLevel(s string) slog.Level {
    switch strings.ToLower(strings.TrimSpace(s)) {
    case "debug":
        return slog.LevelDebug
    case "warn", "warning":
        return slog.LevelWarn
    case "error":
        return slog.LevelError
    default:
        return slog.LevelInfo
    }
}

func IsDebugEnabled() bool {
    return globalLevel.Level() == slog.LevelDebug
}

// Sub returns a logger with a "component" attribute.
//
// The returned logger defers to whatever handler slog.Default() exposes at
// log-write time, so the very common pattern
//
//	var fooLog = logger.Sub("FOO")
//
// at package-init scope still picks up the format and default-attr changes
// applied by Init() in main(). A naive `slog.Default().With(...)` here would
// freeze the bootstrap handler into every package-level logger and Init()
// would only affect call sites that resolve slog.Default() lazily.
func Sub(component string) *slog.Logger {
    return slog.New(&dynamicHandler{
        attrs: []slog.Attr{slog.String("component", component)},
    })
}

// dynamicHandler proxies Enabled/Handle to slog.Default()'s current handler,
// layering any captured attrs and groups on top. Calls to WithAttrs/WithGroup
// accumulate additional layers without freezing the underlying handler.
type dynamicHandler struct {
    attrs  []slog.Attr
    groups []string
}

func (h *dynamicHandler) materialize() slog.Handler {
    inner := slog.Default().Handler()
    for _, g := range h.groups {
        inner = inner.WithGroup(g)
    }
    if len(h.attrs) > 0 {
        inner = inner.WithAttrs(h.attrs)
    }
    return inner
}

func (h *dynamicHandler) Enabled(ctx context.Context, level slog.Level) bool {
    return h.materialize().Enabled(ctx, level)
}

func (h *dynamicHandler) Handle(ctx context.Context, r slog.Record) error {
    return h.materialize().Handle(ctx, r)
}

func (h *dynamicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
    return &dynamicHandler{
        attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
        groups: append([]string{}, h.groups...),
    }
}

func (h *dynamicHandler) WithGroup(name string) slog.Handler {
    return &dynamicHandler{
        attrs:  append([]slog.Attr{}, h.attrs...),
        groups: append(append([]string{}, h.groups...), name),
    }
}

// DefaultAttrs returns the standard service-identity attribute slice for a
// goSignals binary. cluster_name is omitted when empty.
func DefaultAttrs(service, version, nodeID, clusterName string) []slog.Attr {
    attrs := []slog.Attr{
        slog.String("service", service),
        slog.String("version", version),
        slog.String("node_id", nodeID),
    }
    if clusterName != "" {
        attrs = append(attrs, slog.String("cluster_name", clusterName))
    }
    return attrs
}
