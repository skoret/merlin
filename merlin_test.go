// Copyright © 2019. Sergey Skaredov.
// Licensed under the MIT License.
// See LICENSE.txt for details.

package merlin

import (
	"encoding/hex"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/assert"
	"testing"
)

func prt(t *testing.T, message string, t1 Transcript, t2 merlin.Transcript) {
	t.Logf("%s:\n\t%+v\n\t%+v", message, t1, t2)
	t.Log("---------------------------------------------------------------------------")
}

func TestEquivalenceSimple(t *testing.T) {
	t1 := NewTranscript("test protocol")
	t2 := merlin.NewTranscript("test protocol")
	prt(t, "init", *t1, *t2)

	t1.AppendMessage([]byte("some label"), []byte("test data"))
	t2.AppendMessage([]byte("some label"), []byte("test data"))
	prt(t, "add", *t1, *t2)

	c1 := make([]byte, 32)
	t1.ChallengeBytes([]byte("challenge"), c1)
	c2 := t2.ExtractBytes([]byte("challenge"), 32)
	prt(t, "challenge", *t1, *t2)

	t.Logf("challenge bytes:\n\t%s\n\t%s", hex.EncodeToString(c1), hex.EncodeToString(c2))
	assert.Equal(t, c1, c2)
}

// TODO: implement complex tests for transcript and rng
