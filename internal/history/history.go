// Package history persists login attempts, their decoded artifacts, validation
// outcomes, and captured HTTP exchanges.
package history

import (
	"time"

	"github.com/default23/loupe/internal/inspect"
)

// Attempt statuses.
const (
	StatusStarted = "started"
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// Summary holds quick-glance fields shown in the history list.
type Summary struct {
	Subject        string `json:"subject,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Email          string `json:"email,omitempty"`
	ClaimCount     int    `json:"claim_count,omitempty"`
	AttributeCount int    `json:"attribute_count,omitempty"`
}

// Attempt is a single login attempt record.
type Attempt struct {
	ID              int64
	ProfileID       *int64
	ProfileName     string
	Protocol        string
	Status          string
	ExternalBaseURL string
	Error           string
	Summary         Summary
	StartedAt       time.Time
	FinishedAt      *time.Time
}

// HasProfile reports whether the originating profile still exists.
func (a Attempt) HasProfile() bool { return a.ProfileID != nil }

// ProfileIDVal returns the profile ID or 0 if the profile was deleted.
func (a Attempt) ProfileIDVal() int64 {
	if a.ProfileID == nil {
		return 0
	}
	return *a.ProfileID
}

// Details holds the decoded protocol artifacts and validations for an attempt.
type Details struct {
	ParamsUsed  map[string]any       `json:"params_used"`
	Artifacts   map[string]any       `json:"artifacts"`
	Validations []inspect.Validation `json:"validations"`
}

// FullAttempt is an attempt with its details and captured exchanges.
type FullAttempt struct {
	Attempt
	Details   Details
	Exchanges []inspect.Exchange
}

// Filter narrows a history listing.
type Filter struct {
	ProfileID *int64
	Protocol  string
	Status    string
	Limit     int
}
