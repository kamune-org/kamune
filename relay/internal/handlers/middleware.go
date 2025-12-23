package handlers

import (
	"fmt"
	"net/http"

	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/relay/internal/services"
)

func rateLimitMiddleware(
	srvc *services.Service,
) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			switch ok, err := srvc.RateLimit(clientIP(r)); {
			case err != nil:
				grape.ExtractFromErr(ctx, w, fmt.Errorf("rate limit: %w", err))
				return
			case !ok:
				grape.Respond(
					ctx,
					w,
					http.StatusTooManyRequests,
					http.StatusText(http.StatusTooManyRequests),
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
