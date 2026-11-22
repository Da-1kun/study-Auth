package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestRegistrationFinish(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		seed          *pendingChallenge
		issue         bool
		wantStatuses  []int
		wantRemaining int
	}{
		{
			name:         "concurrent requests consume challenge once",
			issue:        true,
			wantStatuses: []int{http.StatusNoContent, http.StatusBadRequest},
		},
		{
			name:         "missing cookie",
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:         "unknown session",
			sessionID:    "unknown",
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:         "expired challenge",
			sessionID:    "expired",
			seed:         &pendingChallenge{operation: registerOperation, expiresAt: time.Now().Add(-time.Minute)},
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:          "wrong operation keeps challenge",
			sessionID:     "login",
			seed:          &pendingChallenge{operation: "login", expiresAt: time.Now().Add(time.Minute)},
			wantStatuses:  []int{http.StatusBadRequest},
			wantRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{sessions: make(map[string]pendingChallenge)}
			sessionID := tt.sessionID
			if tt.seed != nil {
				store.sessions[sessionID] = *tt.seed
			}
			if tt.issue {
				options := httptest.NewRecorder()
				store.handleRegistrationOptions(options, httptest.NewRequest(http.MethodPost, "/register/options", nil))
				cookies := options.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
					t.Fatalf("registration options returned unexpected cookies: %v", cookies)
				}
				sessionID = cookies[0].Value
			}

			statuses := make(chan int, len(tt.wantStatuses))
			for range tt.wantStatuses {
				go func() {
					request := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
					if sessionID != "" {
						request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
					}
					response := httptest.NewRecorder()
					store.handleRegistrationFinish(response, request)
					statuses <- response.Code
				}()
			}

			got := make([]int, 0, len(tt.wantStatuses))
			for range tt.wantStatuses {
				got = append(got, <-statuses)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantStatuses) {
				t.Errorf("finish statuses = %v, want %v", got, tt.wantStatuses)
			}
			if remaining := len(store.sessions); remaining != tt.wantRemaining {
				t.Errorf("remaining sessions = %d, want %d", remaining, tt.wantRemaining)
			}
		})
	}
}
