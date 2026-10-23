package main

import (
	"log"
	"net/http"
	"time"
)

// statusRecorder は WriteHeader を横取りしてステータスコードを記録する ResponseWriter。
// ハンドラが WriteHeader を呼ばずに Write した場合は 200 なので、初期値を 200 にしておく。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logRequests はブラウザから来た全リクエストをログに出すミドルウェア。
// 以降のステップで /callback?code=...&state=... のようなクエリや、
// 302 の Location ヘッダをここで観察する。
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		line := "<- " + r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		log.Printf("%s -> %d (%s)", line, rec.status, time.Since(start).Round(time.Millisecond))
		if loc := rec.Header().Get("Location"); loc != "" {
			log.Printf("   Location: %s", loc)
		}
	})
}
