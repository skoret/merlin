// Copyright © 2019. Sergey Skaredov.
// Licensed under the MIT License.
// See LICENSE.txt for details.

// Implementation of Merlin transcripts construction,
//	invented by Henry de Valence, Isis Lovecruft and Oleg Andreev
// About: https://merlin.cool/index.html
// References:
//	dalek-cryptography: https://github.com/dalek-cryptography/merlin
//	Henry de Valence: 	https://github.com/hdevalence/libmerlin
//	George Tankersley:  https://github.com/gtank/merlin

package merlin

import (
	"encoding/binary"
	. "github.com/skoret/merlin/strobe"
	"io"
)

const (
	ProtocolLabel   = "Merlin v1.0"
	DomainSeparator = "dom-sep"
	MaxBufferLength = 1 << 32
)

func encodeU32(u32 uint32) []byte {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], u32)
	return bytes[:]
}

func encodeU64(u64 uint64) []byte {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], u64)
	return bytes[:]
}

type Transcript struct {
	strobe Strobe
}

// Initialize new Merlin transcript object
// with a label — an application-specific domain separator
func NewTranscript(label string) *Transcript {
	t := Transcript{
		strobe: NewStrobe(ProtocolLabel),
	}

	bytes := encodeU32(uint32(len([]byte(label))))
	t.strobe.MetaAd([]byte(DomainSeparator), false)
	t.strobe.MetaAd(bytes, true)
	t.strobe.Ad([]byte(label), false)
	return &t
}

// Add the message from src parameter to the transcript with the supplied label
// AD[label || LE32(len(message))](message);
func (t *Transcript) AppendMessage(label []byte, src []byte) {
	storeMeta(&t.strobe, label, src)
	t.strobe.Ad(src, false)
}

func (t *Transcript) AppendU64(label []byte, u64 uint64) {
	t.AppendMessage(label, encodeU64(u64))
}

// Extract sequence of verifiers's challenge bytes to data parameter
// dest <- PRF[label || LE32(dest.len())]();
func (t *Transcript) ChallengeBytes(label []byte, dest []byte) {
	storeMeta(&t.strobe, label, dest)
	t.strobe.Prf(dest, false)
}

func storeMeta(strobe *Strobe, label []byte, data []byte) {
	length := len(data)
	if length > MaxBufferLength {
		panic("Buffer length " + string(length) + " is more then max allowed (2^32)")
	}
	bytes := encodeU32(uint32(length))
	strobe.MetaAd(label, false)
	strobe.MetaAd(bytes, true)
}

// Use TranscriptRngBuilder to rekey the Transcript with witness data
// and then to finalize it with an external rng to a TranscriptRng.
type TranscriptRngBuilder struct {
	strobe Strobe
}

func (t *Transcript) BuildRng() TranscriptRngBuilder {
	return TranscriptRngBuilder{
		t.strobe.Clone(),
	}
}

// Rekey the transcript using the provided witness src
// The label parameter is metadata about witness
// KEY[label || LE32(witness.len())](witness);
func (t *TranscriptRngBuilder) RekeyWithWitness(label []byte, src []byte) {
	storeMeta(&t.strobe, label, src)
	t.strobe.Key(src, false)
}

// Use the supplied external rng to rekey the transcript, so
// that the finalized TranscriptRng is a PRF bound to
// randomness from the external RNG, as well as all other
// transcript data.
// KEY[b"rng"](rng);
func (t *TranscriptRngBuilder) Finalize(rng io.Reader) *TranscriptRng {
	entropy := make([]byte, 32)
	_, _ = rng.Read(entropy)

	t.strobe.MetaAd([]byte("rng"), false)
	t.strobe.Key(entropy, false)

	return &TranscriptRng{
		t.strobe.Clone(),
	}
}

type TranscriptRng struct {
	strobe Strobe
}

// Generate len(dest) synthetic random bytes
// based on full transcript history and randomness from rng
// and write them into dest buffer.
// Possible improvements if len(dest) > 2^32:
//	* read 2^32 bytes and return (2^32, err)
//	* read len(dest) bytes in q+1 iterations, where
//		q = len(dest) / 2^32 with length 2^32
//		and the last with length r = len(dest) % 2^32 != 0
func (t *TranscriptRng) Read(dest []byte) (n int, err error) {
	n, err = len(dest), nil
	if n > MaxBufferLength {
		panic("Buffer length " + string(n) + " is more then max allowed (2^32)")
	}
	bytes := encodeU32(uint32(n))
	t.strobe.MetaAd(bytes, false)
	t.strobe.Prf(dest, false)
	return
}
