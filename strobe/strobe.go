// Copyright © 2019. Sergey Skaredov.
// Licensed under the MIT License.
// See LICENSE.txt for details.

// Partial implementation of Strobe protocol,
//	invented by Mike Hamburg
// Specs: https://strobe.sourceforge.io/specs/
// References:
//	Mike Hamburg:	  	https://strobe.sourceforge.io/code/
//	David Wong:		  	https://github.com/mimoo/StrobeGo
//	Henry de Valence: 	https://github.com/hdevalence/libmerlin/blob/master/src/merlin.c
//	dalek-cryptography: https://github.com/dalek-cryptography/merlin/blob/master/src/strobe.rs
//
// Probably it will be a full implementation someday

package strobe

import "encoding/binary"

// Default Strobe parameters
const (
	KeccakBlockSize = 25  // let b = KeccakBlockSize * 64, i.e. either 400, 800 or 1600 for keccak-f[b]
	SecLevel        = 128 // a target security level, either 128 or 256 bits
	rate            = 166 // 'R' parameter from spec = [b/8 - sec/4 - 2] is the number of bytes in a Strobe block
	StrobeVersion   = "1.0.2"
)

type flag uint8

const (
	flagI flag = 1 << iota // inbound/outbound
	flagA                  // application
	flagC                  // cipher
	flagT                  // transport [unsupported]
	flagM                  // meta
	flagK                  // keytree [unsupported]
)

// Only `meta-AD`, `AD`, `KEY`, and `PRF` operations are supported
const (
	ad  = flagA
	key = flagA | flagC
	prf = flagI | flagA | flagC
	//send_clr = flagA | flagT
	//recv_clr = flagI | flagA | flagT
	//send_enc = flagA | flagC | flagT
	//recv_enc = flagI | flagA | flagC | flagT
	//send_mac = flagC | flagT
	//recv_mac = flagI | flagC | flagT
	//ratchet  = flagC

	metaAd = flagA | flagM
)

type Strobe struct {
	flags    flag                    // current operation flags
	bytes    []byte                  // bytes of state
	state    [KeccakBlockSize]uint64 // internal keccak-f state
	pos      uint8
	posBegin uint8
}

func NewStrobe(label string) (s Strobe) {
	s.bytes = make([]byte, KeccakBlockSize*8)

	copy(s.bytes[:6], []byte{1, rate + 2, 1, 0, 1, 96})
	copy(s.bytes[6:13], "STROBEv")
	copy(s.bytes[13:], StrobeVersion)

	bytesToState(&s.state, s.bytes)
	keccakF1600(&s.state)
	stateToBytes(s.state, s.bytes)

	s.MetaAd([]byte(label), false)
	return
}

func (s *Strobe) Ad(data []byte, more bool) {
	s.beginOp(ad, more)
	s.absorb(data)
}

func (s *Strobe) MetaAd(data []byte, more bool) {
	s.beginOp(metaAd, more)
	s.absorb(data)
}

func (s *Strobe) Prf(data []byte, more bool) {
	s.beginOp(prf, more)
	s.squeeze(data)
}

func (s *Strobe) Key(data []byte, more bool) {
	s.beginOp(key, more)
	s.overwrite(data)
}

func (s *Strobe) Clone() (clone Strobe) {
	clone = *s
	clone.bytes = make([]byte, len(s.bytes))
	copy(clone.bytes, s.bytes)
	return
}

func stateToBytes(state [25]uint64, bytes []byte) {
	for i := 0; len(bytes) >= 8; i++ {
		binary.LittleEndian.PutUint64(bytes, state[i])
		bytes = bytes[8:]
	}
}

func bytesToState(state *[25]uint64, bytes []byte) {
	for i := range state {
		state[i] = binary.LittleEndian.Uint64(bytes)
		bytes = bytes[8:]
	}
}

func (s *Strobe) absorb(data []byte) {
	for i := range data {
		s.bytes[s.pos] ^= data[i]
		s.pos += 1
		if s.pos == rate {
			s.runF()
		}
	}
}

func (s *Strobe) squeeze(data []byte) {
	for i := range data {
		data[i] = s.bytes[s.pos]
		s.bytes[s.pos] = 0
		s.pos += 1
		if s.pos == rate {
			s.runF()
		}
	}
}

func (s *Strobe) overwrite(data []byte) {
	for i := range data {
		s.bytes[s.pos] = data[i]
		s.pos += 1
		if s.pos == rate {
			s.runF()
		}
	}
}

// Sponge function F
func (s *Strobe) runF() {
	s.bytes[s.pos] ^= s.posBegin
	s.bytes[s.pos+1] ^= 0x04
	s.bytes[rate+1] ^= 0x80

	bytesToState(&s.state, s.bytes)
	keccakF1600(&s.state)
	stateToBytes(s.state, s.bytes) // this should be more elegant

	s.pos = 0
	s.posBegin = 0
}

func (s *Strobe) beginOp(flags flag, more bool) {
	if more {
		if flags != s.flags {
			panic("Trying to continue operation with different flags")
		}
		// don't start new operation if continuation is requested
		return
	}

	oldBegin := s.posBegin
	s.posBegin = s.pos + 1
	s.flags = flags
	s.absorb([]byte{oldBegin, byte(flags)})

	forceF := (flags & flagC) != 0
	if forceF && s.pos != 0 {
		s.runF()
	}
}
