// Copyright © 2019. Sergey Skaredov.
// Licensed under the MIT License.
// See LICENSE.txt for details.

package merlin

import (
	"encoding/hex"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/assert"
	"io"
	"math/rand"
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

	t1.AppendMessage([]byte("test label"), []byte("test data"))
	t2.AppendMessage([]byte("test label"), []byte("test data"))
	prt(t, "add", *t1, *t2)

	c1 := make([]byte, 32)
	t1.ChallengeBytes([]byte("challenge"), c1)
	c2 := t2.ExtractBytes([]byte("challenge"), 32)
	prt(t, "challenge", *t1, *t2)

	t.Logf("challenge bytes:\n\t%s\n\t%s", hex.EncodeToString(c1), hex.EncodeToString(c2))
	assert.Equal(t, c1, c2)
}

func TestEquivalenceComplex(t *testing.T) {
	t1 := NewTranscript("test protocol")
	t2 := merlin.NewTranscript("test protocol")
	prt(t, "init", *t1, *t2)

	t1.AppendMessage([]byte("test label"), []byte("test data"))
	t2.AppendMessage([]byte("test label"), []byte("test data"))
	prt(t, "add", *t1, *t2)

	lorem := make([]byte, 1024)
	for i := range lorem {
		lorem[i] = 239
	}

	var c1, c2 []byte = make([]byte, 32), nil

	for i := 0; i < 32; i++ {
		t1.ChallengeBytes([]byte("challenge"), c1)
		c2 = t2.ExtractBytes([]byte("challenge"), 32)

		assert.Equal(t, c1, c2)

		t1.AppendMessage([]byte("lorem ipsum"), lorem)
		t2.AppendMessage([]byte("lorem ipsum"), lorem)

		t1.AppendMessage([]byte("challenge data"), lorem)
		t2.AppendMessage([]byte("challenge data"), lorem)
	}

	prt(t, "final state", *t1, *t2)
	t.Logf("challenge bytes:\n\t%s\n\t%s", hex.EncodeToString(c1), hex.EncodeToString(c2))
	assert.Equal(t, c1, c2)
}

func TestTranscriptRngBound(t *testing.T) {
	label := "label"
	commitment := "commitment"
	witness := "witness"
	src := rand.NewSource(239)
	rng := rand.New(src)

	r1 := build(label, commitment, witness+"1", rng)
	r2 := build(label, commitment, witness+"2", rng)
	r3 := build(label, commitment, witness+"3", rng)
	r4 := build(label, commitment, witness+"4", rng)

	s1 := generate(t, r1)
	s2 := generate(t, r2)
	s3 := generate(t, r3)
	s4 := generate(t, r4)

	assert.NotEqual(t, s1, s2)
	assert.NotEqual(t, s1, s3)
	assert.NotEqual(t, s1, s4)

	assert.NotEqual(t, s2, s3)
	assert.NotEqual(t, s2, s4)

	assert.NotEqual(t, s3, s4)

	t.Log("random bytes (in hex) per witnesses:")
	t.Logf("%s1: %s", witness, hex.EncodeToString(s1))
	t.Logf("%s2: %s", witness, hex.EncodeToString(s2))
	t.Logf("%s3: %s", witness, hex.EncodeToString(s3))
	t.Logf("%s4: %s", witness, hex.EncodeToString(s4))
}

func build(label, commitment, witness string, rng io.Reader) *TranscriptRng {
	t := NewTranscript(label)
	t.AppendMessage([]byte("commitment"), []byte(commitment))

	b := t.BuildRng()
	b.RekeyWithWitness([]byte("witness"), []byte(witness))
	return b.Finalize(rng)
}

func generate(t *testing.T, rnd io.Reader) []byte {
	dest := make([]byte, 32)
	n, err := rnd.Read(dest)
	if err != nil {
		panic("Unable to get random bytes")
	}
	assert.Equal(t, 32, n)
	return dest
}
