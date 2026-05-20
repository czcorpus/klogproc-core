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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testAppID  = "myapp"
	testSecret = "s3cr3t"
)

func makeTestKey(appID, secret string, dt time.Time, interval string) string {
	return generateAPIReportingKey(appID, secret, dt, durationStringToDTPrefix(interval))
}

// TestValidateAPIReportingKeyExactTime checks that a key validates successfully
// when the validation time equals the generation time, for all supported TTLs.
func TestValidateAPIReportingKeyExactTime(t *testing.T) {
	now := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)
	for _, interval := range []string{
		APIReportingKeyTTLOneMinute,
		APIReportingKeyTTLTenMinutes,
		APIReportingKeyTTLOneHour,
		APIReportingKeyTTLTenHours,
		APIReportingKeyTTLOneDay,
	} {
		key := makeTestKey(testAppID, testSecret, now, interval)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, now, interval)
		assert.NoError(t, err, "interval=%s", interval)
		assert.True(t, ok, "interval=%s", interval)
	}
}

// TestValidateAPIReportingKeyWithinWindow checks that validation succeeds within
// the tolerance window, which is interval-dependent:
//   - 1m TTL:  ±1 minute  (tight — a 5m window would negate the 1m rotation)
//   - others:  ±5 minutes
func TestValidateAPIReportingKeyWithinWindow(t *testing.T) {
	base := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)

	t.Run("1m_validated_1m_after_generation", func(t *testing.T) {
		// candidate dt-1m = 14:25 matches the key generated at 14:25
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(time.Minute), APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("1m_validated_1m_before_generation", func(t *testing.T) {
		// candidate dt+1m = 14:25 matches the key generated at 14:25
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(-time.Second*30), APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("10m_validated_5m_after_generation", func(t *testing.T) {
		// candidate dt-5m = 14:25 shares the 10-minute prefix "14:2" with 14:25
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLTenMinutes)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(5*time.Minute), APIReportingKeyTTLTenMinutes)
		assert.NoError(t, err)
		assert.True(t, ok)
	})
}

// TestValidateAPIReportingKeyOutsideWindow checks that validation fails when the
// validation time exceeds the interval-specific tolerance.
func TestValidateAPIReportingKeyOutsideWindow(t *testing.T) {
	base := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)

	t.Run("1m_validated_2m_after_generation", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(2*time.Minute), APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("1m_validated_2m_before_generation", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(-2*time.Minute), APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("10m_validated_10m_after_generation", func(t *testing.T) {
		// At 14:35 all three candidates (14:30, 14:35, 14:40) have prefix "14:3",
		// so the key generated at 14:25 (prefix "14:2") is no longer accepted.
		key := makeTestKey(testAppID, testSecret, base, APIReportingKeyTTLTenMinutes)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, base.Add(10*time.Minute), APIReportingKeyTTLTenMinutes)
		assert.NoError(t, err)
		assert.False(t, ok)
	})
}

// TestValidateAPIReportingKeyTimezoneIndependence checks that keys generated and
// validated with different timezone representations of the same instant are equal.
func TestValidateAPIReportingKeyTimezoneIndependence(t *testing.T) {
	utcTime := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)
	cetTime := utcTime.In(time.FixedZone("CET", 2*60*60)) // same instant, UTC+2 → 16:25 local

	t.Run("key_generated_in_local_time_validates_against_utc", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, cetTime, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, utcTime, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("key_generated_in_utc_validates_against_local_time", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, utcTime, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, cetTime, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.True(t, ok)
	})
}

// TestValidateAPIReportingKeyWrongCredentials checks that a tampered or wrong key
// is rejected without returning an error.
func TestValidateAPIReportingKeyWrongCredentials(t *testing.T) {
	now := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)

	t.Run("wrong_secret", func(t *testing.T) {
		key := makeTestKey(testAppID, "wrong", now, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, now, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("wrong_app_id", func(t *testing.T) {
		key := makeTestKey("otherapp", testSecret, now, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, now, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("garbage_key", func(t *testing.T) {
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, "notavalidkey", now, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})
}

// TestValidateAPIReportingKeyInvalidInterval checks that an unsupported refresh
// interval string causes an error to be returned.
func TestValidateAPIReportingKeyInvalidInterval(t *testing.T) {
	now := time.Date(2026, 5, 20, 14, 25, 0, 0, time.UTC)
	key := makeTestKey(testAppID, testSecret, now, APIReportingKeyTTLOneMinute)
	_, err := ValidateAPIReportingKey(testAppID, testSecret, key, now, "2h")
	assert.Error(t, err)
}

// TestValidateAPIReportingKeyMidnightCrossing covers the case where a key is
// generated near the end of a day (23:59) and validated shortly after midnight
// (00:02) — a 3-minute gap that crosses a day boundary.
//
// The validation produces three candidate times from the validation moment:
// 23:57 (day D), 00:02 (day D+1), 00:07 (day D+1).
//
// Whether the key is accepted depends on whether the TTL prefix is coarse enough
// that the 23:57 candidate shares the same prefix as the 23:59 generation time:
//
//   - 1m  (prefix "HH:MM"):  23:57 ≠ 23:59  →  fails
//   - 10m (prefix "HH:M"):   23:57 = 23:5x  →  passes
//   - 1h  (prefix "HH"):     23:57 = 23     →  passes
//   - 10h (prefix "H-tens"): 23:57 = 2x     →  passes
//   - 1d  (prefix "date"):   23:57 = same day → passes
func TestValidateAPIReportingKeyMidnightCrossing(t *testing.T) {
	genTime := time.Date(2026, 1, 2, 23, 59, 0, 0, time.UTC)
	valTime := time.Date(2026, 1, 3, 0, 2, 0, 0, time.UTC)

	t.Run("1m_fails", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, genTime, APIReportingKeyTTLOneMinute)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, valTime, APIReportingKeyTTLOneMinute)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("10m_passes", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, genTime, APIReportingKeyTTLTenMinutes)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, valTime, APIReportingKeyTTLTenMinutes)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("1h_passes", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, genTime, APIReportingKeyTTLOneHour)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, valTime, APIReportingKeyTTLOneHour)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("10h_passes", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, genTime, APIReportingKeyTTLTenHours)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, valTime, APIReportingKeyTTLTenHours)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("1d_passes", func(t *testing.T) {
		key := makeTestKey(testAppID, testSecret, genTime, APIReportingKeyTTLOneDay)
		ok, err := ValidateAPIReportingKey(testAppID, testSecret, key, valTime, APIReportingKeyTTLOneDay)
		assert.NoError(t, err)
		assert.True(t, ok)
	})
}
