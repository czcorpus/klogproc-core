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
	"context"
	"fmt"

	"github.com/czcorpus/klogproc-core/save"
	"github.com/czcorpus/klogproc-core/storage"

	"github.com/rs/zerolog/log"
)

// RunOnTheFlyWriteConsumer starts a log record data consumer (and writer) for logs not coming from files
// but rather directly by sending them from other part of an application.
//
// Unlike the RunWriteConsumer, this function works for any "app type", i.e. it is not necessary to call
// this (and thus create a new consumer goroutine) for each logged service. The function keeps chunks for
// multiple logged services at once.
func RunOnTheFlyWriteConsumer(ctx context.Context, conf *ConnectionConf, incomingData <-chan *storage.OnTheFlyOutputRecord) <-chan error {
	chunks := make(map[string]*appBulkChunk)
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if ctx.Err() != nil {
				var dropped int
				for _, chunk := range chunks {
					dropped += chunk.idx / 2
				}
				if dropped > 0 {
					log.Warn().Int("droppedRecords", dropped).Msg("closing log write consumer due to cancellation, some buffered records were not flushed")
				}
				close(errChan)
				return
			}
			for appType, chunk := range chunks {
				if chunk.isUnfinished() {
					dataToSend := chunk.prepareForSending()
					if err := BulkWriteRequest(ctx, dataToSend, appType, conf); err != nil {
						select {
						case errChan <- err:
						default:
							log.Error().Err(err).Msg("errChan full during shutdown flush, dropping error")
						}
					}
					chunk.reset()
				}
			}
			close(errChan)
		}()
		for {
			select {
			case rec, ok := <-incomingData:
				if !ok {
					return
				}

				pushChunkSize := conf.GetPushChunkSize(rec.AppType)

				if chunks[rec.AppType] == nil {
					chunks[rec.AppType] = &appBulkChunk{
						chunkSize: pushChunkSize,
						data:      make([][]byte, pushChunkSize*2+1),
					}
				}
				chunk := chunks[rec.AppType]

				jsonData, err := rec.ToJSON()
				recType := es6DocType
				index := fmt.Sprintf("%s_%s", conf.Index, rec.AppType)
				if conf.MajorVersion < 6 {
					recType = rec.GetType()
					index = conf.Index
				}
				jsonMeta := CNKRecordMeta{
					ID:    rec.GetID(),
					Type:  recType,
					Index: index,
				}
				jsonMetaES, err2 := (&ESCNKRecordMeta{Index: jsonMeta}).ToJSON()

				if err != nil {
					log.Error().Err(err).Msgf("Failed to encode item %s", rec.GetID())
					select {
					case errChan <- err:
					case <-ctx.Done():
						return
					}
				} else if err2 != nil {
					log.Error().Err(err2).Msgf("Failed to encode a 'meta' record for item %s", rec.GetID())
					select {
					case errChan <- err2:
					case <-ctx.Done():
						return
					}
				} else {
					chunk.addData(jsonMetaES, jsonData)
					if chunk.isFull() {
						dataToSend := chunk.prepareForSending()
						if err := BulkWriteRequest(ctx, dataToSend, rec.AppType, conf); err != nil {
							select {
							case errChan <- err:
							case <-ctx.Done():
								return
							}
						}
						chunk.reset()
					}
				}

			case <-ctx.Done():
				log.Info().Msg("closing log write consumer due to cancellation")
				return
			}
		}
	}()

	return errChan
}

// ----

// RunWriteConsumer reads incoming records from incomingData channel and writes them
// chunk by chunk. Once the channel is closed, the rest of items in buffer is writtten
// and the consumer finishes.
func RunWriteConsumer(ctx context.Context, appType string, conf *ConnectionConf, incomingData <-chan *storage.BoundOutputRecord) <-chan save.ConfirmMsg {
	// Elasticsearch bulk writes
	confirmChan := make(chan save.ConfirmMsg)
	go func() {
		if conf.IsConfigured() {
			i := 0
			appType = storage.MapAppTypeToIndex(appType)
			data := make([][]byte, conf.PushChunkSize*2+1)
			var chunkPosition *storage.LogRange
			var esErr error
			var rec *storage.BoundOutputRecord

			defer func() {
				if i > 0 && ctx.Err() == nil && chunkPosition != nil && rec != nil {
					data[i] = []byte("\n")
					esErr = BulkWriteRequest(ctx, data[:i+1], appType, conf)
					chunkPosition.Written = esErr == nil
					confirmMsg := save.ConfirmMsg{
						FilePath: rec.FilePath,
						Position: *chunkPosition,
						Error:    esErr,
					}
					confirmChan <- confirmMsg
				}
				close(confirmChan)
			}()

			for {
				select {
				case rec, ok := <-incomingData:
					if !ok {
						return
					}
					if chunkPosition == nil {
						chunkPosition = &rec.FilePos
					}
					chunkPosition.SeekEnd = rec.FilePos.SeekEnd
					jsonData, err := rec.ToJSON()
					recType := es6DocType
					index := fmt.Sprintf("%s_%s", conf.Index, appType)
					if conf.MajorVersion < 6 {
						recType = rec.GetType()
						index = conf.Index
					}
					jsonMeta := CNKRecordMeta{
						ID:    rec.GetID(),
						Type:  recType,
						Index: index,
					}
					jsonMetaES, err2 := (&ESCNKRecordMeta{Index: jsonMeta}).ToJSON()

					if err != nil {
						log.Error().Err(err).Msgf("Failed to encode item %s", rec.GetID())

					} else if err2 != nil {
						log.Error().Err(err2).Msgf("Failed to encode a 'meta' record for item %s", rec.GetID())

					} else {
						data[i] = jsonMetaES
						data[i+1] = jsonData
						i += 2
					}
					if i == conf.PushChunkSize*2 {
						data[i] = []byte("\n")
						esErr = BulkWriteRequest(ctx, data[:i+1], appType, conf)
						chunkPosition.Written = true
						if esErr != nil {
							dataCopy := make([][]byte, len(data[:i+1]))
							go func() {
								log.Warn().Err(esErr).Msg("due to inserting error, klogproc will try to insert smaller chunks")
								copy(dataCopy, data[:i+1])
								WriteBulkWithError(ctx, dataCopy, appType, conf)
							}()
						}
						confirmMsg := save.ConfirmMsg{
							FilePath: rec.FilePath,
							Position: *chunkPosition,
							Error:    esErr,
						}
						confirmChan <- confirmMsg
						i = 0
					}

				case <-ctx.Done():
					i = 0
					log.Info().Msg("closing log write consumer due to cancellation")
					return
				}

			}

		} else {
			for {
				select {
				case _, ok := <-incomingData:
					if !ok {
						return
					}
				case <-ctx.Done():
					log.Info().Msg("closing log write consumer due to cancellation")
					return
				}
			}
		}
	}()
	return confirmChan
}
