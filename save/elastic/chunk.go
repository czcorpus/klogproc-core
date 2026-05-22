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

import "fmt"

type appBulkChunk struct {
	data      [][]byte
	chunkSize int
	idx       int
}

func (chunk *appBulkChunk) String() string {
	return fmt.Sprintf("appBulkChunk{chunkSize: %d, idx: %d}", chunk.chunkSize, chunk.idx)
}

func (chunk *appBulkChunk) isFull() bool {
	return chunk.idx == chunk.chunkSize*2
}

func (chunk *appBulkChunk) prepareForSending() [][]byte {
	chunk.data[chunk.idx] = []byte("\n")
	return chunk.data[:chunk.idx+1]
}

func (chunk *appBulkChunk) reset() {
	chunk.idx = 0
}

func (chunk *appBulkChunk) isUnfinished() bool {
	return chunk.idx > 0
}

func (chunk *appBulkChunk) addData(metadata, data []byte) {
	chunk.data[chunk.idx] = metadata
	chunk.data[chunk.idx+1] = data
	chunk.idx += 2
}
