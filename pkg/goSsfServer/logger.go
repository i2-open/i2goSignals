package goSsfServer

import (
	"net/http"
	"time"

	"github.com/i2-open/i2goSignals/pkg/logger"
)

var httpLog = logger.Sub("HTTP")

func (sa *SsfApplication) Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		inner.ServeHTTP(w, r)

		httpLog.Info("Request",
			"db", sa.Provider.Name(),
			"method", r.Method,
			"uri", r.RequestURI,
			"handler", name,
			"duration", time.Since(start),
		)
	})
}
