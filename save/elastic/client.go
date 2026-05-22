// Copyright 2017 Tomas Machalek <tomas.machalek@gmail.com>
// Copyright 2017 Institute of the Czech National Corpus,
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

package elastic

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	es6DocType = "_doc"
)

// ESImportFailHandler represents an object able to handle (valid)
// log items we failed to insert to ElasticSearch (typically due
// to inavailability)
type ESImportFailHandler interface {
	RescueFailedChunks(chunk [][]byte) error
}

// ----

func BulkWriteRequest(ctx context.Context, data [][]byte, appType string, esconf *ConnectionConf) error {
	esclient := NewClient(esconf, appType)
	q := bytes.Join(data, []byte("\n"))
	_, err := esclient.DoBulkRequest(ctx, "POST", "/_bulk", q)
	if err != nil {
		return fmt.Errorf("failed to push log chunk: %w", err)
	}
	log.Debug().Msgf("Inserted chunk of %d items to ElasticSearch", (len(data)-1)/2)
	return nil
}

// WriteBulkWithError is used for data where at least one error is expected.
// It splits data into two halfs and tries to insert them independently.
// Then it works recursively until chunks are inserted all small enough to
// stop. This allows for not dropping a whole chunk because of a single error
// (or few errors). The action itself is not recoverable so in case it fails
// from any reason, the items we wanted to write are definitely lost.
func WriteBulkWithError(ctx context.Context, data [][]byte, appType string, esconf *ConnectionConf) {
	if len(data) <= 10 {
		data = append(data, []byte("\n"))
		if err := BulkWriteRequest(ctx, data, appType, esconf); err != nil {
			log.Error().Err(err).Int("chunkSize", len(data)).Msg("failed to insert exploded chunk")

		} else {
			log.Info().Int("chunkSize", len(data)).Msg("successfully inserted exploded chunk ")
		}

	} else {
		if len(data)%2 == 1 { // => original chunk with newline at the end
			data = data[:len(data)-1]
		}
		split := len(data) / 2
		data1 := data[:split]
		time.Sleep(2 * time.Second)
		WriteBulkWithError(ctx, data1, appType, esconf)
		data2 := data[split:]
		time.Sleep(2 * time.Second)
		WriteBulkWithError(ctx, data2, appType, esconf)
	}
}
