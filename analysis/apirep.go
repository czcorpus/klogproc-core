// Copyright 2026 Tomas Machalek <tomas.machalek@gmail.com>
// Copyright 2026 Department of Linguistics,
//                Faculty of Arts, Charles University
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analysis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	APIReportingKeyTTLOneDay     = "1d"
	APIReportingKeyTTLTenHours   = "10h"
	APIReportingKeyTTLOneHour    = "1h"
	APIReportingKeyTTLTenMinutes = "10m"
	APIReportingKeyTTLOneMinute  = "1m"
)

func validateRefreshInterval(refresh string) error {
	if refresh == APIReportingKeyTTLOneDay || refresh == APIReportingKeyTTLTenHours ||
		refresh == APIReportingKeyTTLOneHour || refresh == APIReportingKeyTTLTenMinutes ||
		refresh == APIReportingKeyTTLOneMinute {
		return nil
	}
	return fmt.Errorf("invalid API key refresh interval: %s, use 1d, 10h, 1h, 10m, 1m", refresh)
}

func getDTCandidates(dt time.Time) []time.Time {
	times := make([]time.Time, 7)
	for i := -3; i <= 3; i++ {
		times[i+3] = dt.Add(time.Duration(i) * time.Minute)
	}
	return times
}

func durationStringToDTPrefix(ds string) int {
	switch ds {
	case APIReportingKeyTTLOneDay:
		return 10
	case APIReportingKeyTTLTenHours:
		return 12
	case APIReportingKeyTTLOneHour:
		return 13
	case APIReportingKeyTTLTenMinutes:
		return 15
	case APIReportingKeyTTLOneMinute:
		return 16
	default:
		return 0
	}
}

func generateAPIReportingKey(appID, secret string, dt time.Time, dtPrefixSize int) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(appID + ":" + dt.UTC().Format(time.RFC3339)[:dtPrefixSize]))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateAPIReportingKey checks whether a request header token comes from a
// known in-house web application. Each such application attaches a token to its
// outgoing requests by HMAC-signing a string composed of its app ID and a
// truncated UTC timestamp (the prefix length is determined by refreshInterval,
// so the token rotates on that cadence). The validator re-derives the expected
// token for the given instant — plus candidates slightly before and after to
// absorb clock skew — and accepts the request if any candidate matches.
//
// A positive result does not grant authorisation; it is used solely to
// distinguish in-house traffic from third-party API usage in request logs.
func ValidateAPIReportingKey(appID, secret, key string, dt time.Time, refreshInterval string) (bool, error) {
	if err := validateRefreshInterval(refreshInterval); err != nil {
		return false, fmt.Errorf("cannot validate api reporting key: %w", err)
	}
	for _, dtCandidate := range getDTCandidates(dt) {
		expected := generateAPIReportingKey(appID, secret, dtCandidate, durationStringToDTPrefix(refreshInterval))
		fmt.Println("testing candidate ", dtCandidate.Format(time.RFC3339), ", key: ", expected, ", incom: ", key)
		if hmac.Equal([]byte(key), []byte(expected)) {
			return true, nil
		}
	}
	return false, nil
}
