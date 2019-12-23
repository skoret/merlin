// Copyright © 2019. Sergey Skaredov.
// Licensed under the MIT License.
// See LICENSE.txt for details.

package strobe

import (
	"encoding/hex"
	"github.com/mimoo/StrobeGo/strobe"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
	"time"
)

func elapse(t *testing.T, description string, action func()) {
	total := time.Duration(0)

	for i := 0; i < rounds; i++ {
		start := time.Now()
		action()
		total += time.Since(start)
	}

	elapsed := time.Duration(total.Nanoseconds() / rounds)
	t.Logf("%s elapsed in %v", description, elapsed)
}

func getState(s strobe.Strobe) reflect.Value {
	v := reflect.ValueOf(s)
	return v.FieldByName("a")
}

func assertStrobes(t *testing.T, s1 Strobe, s2 strobe.Strobe) {
	state := getState(s2)
	for i := 0; i < state.Len(); i++ {
		elem := state.Index(i).Uint()
		assert.Equal(t, s1.state[i], elem, "states aren't the same")
	}
}

const rounds = 1000

func TestInit(t *testing.T) {
	s1 := NewStrobe(t.Name())
	s2 := strobe.InitStrobe(t.Name(), SecLevel)

	assertStrobes(t, s1, s2)

	elapse(t, t.Name()+"Mini", func() {
		NewStrobe(t.Name())
	})

	elapse(t, t.Name()+"Mimo", func() {
		strobe.InitStrobe(t.Name(), SecLevel)
	})

	t.Logf("position: %d", s1.pos)
	t.Logf("%+v", s1.state)
	t.Logf("%+v", getState(s2))
}

func TestAd(t *testing.T) {
	data := []byte(" very long data to force F: AAAAAAOOOOOOOOOAAAOAOAOAOAOAO, mmmmmmmmmmmmmmmmm")

	s1 := NewStrobe(t.Name())
	s2 := strobe.InitStrobe(t.Name(), SecLevel)

	s1.Ad([]byte(t.Name()), false)
	s1.Ad(data, true)
	s1.Ad(data, true)

	s2.AD(false, []byte(t.Name()))
	s2.Operate(false, "AD", data, 0, true)
	s2.Operate(false, "AD", data, 0, true)

	assertStrobes(t, s1, s2)

	elapse(t, t.Name()+"Mini", func() {
		s := NewStrobe(t.Name())
		s.Ad([]byte(t.Name()), false)
		s.Ad(data, true)
		s.Ad(data, true)
	})

	elapse(t, t.Name()+"Mimo", func() {
		s := strobe.InitStrobe(t.Name(), SecLevel)
		s.AD(false, []byte(t.Name()))
		s.Operate(false, "AD", data, 0, true)
		s.Operate(false, "AD", data, 0, true)
	})

	t.Logf("position: %d", s1.pos)
	t.Logf("%+v", s1.state)
	t.Logf("%+v", getState(s2))
}

func TestPrf(t *testing.T) {
	s1 := NewStrobe(t.Name())
	s2 := strobe.InitStrobe(t.Name(), SecLevel)
	prf1, prf2 := make([]byte, 32), make([]byte, 32)

	s1.Ad([]byte(t.Name()), false)
	s1.Prf(prf1[:], false)

	s2.AD(false, []byte(t.Name()))
	prf2 = s2.PRF(len(prf2))

	assertStrobes(t, s1, s2)
	assert.Equal(t, prf1, prf2, "prf returned bytes aren't the same")

	elapse(t, t.Name()+"Mini", func() {
		s := NewStrobe(t.Name())
		s.Ad([]byte(t.Name()), false)
		s.Prf(prf1[:], false)
	})

	elapse(t, t.Name()+"Mimo", func() {
		s := strobe.InitStrobe(t.Name(), SecLevel)
		s.AD(false, []byte(t.Name()))
		prf2 = s.PRF(len(prf2))
	})

	t.Logf("position: %d", s1.pos)
	t.Logf("s1 state: %v", s1.state)
	t.Logf("s2 state: %v", getState(s2))
	t.Logf("s1 prf32: %v | %s", prf1, hex.EncodeToString(prf1))
	t.Logf("s2 prf32: %v | %s", prf2, hex.EncodeToString(prf2))
}

func TestKey(t *testing.T) {
	key := []byte("secret key")
	data := []byte(" very long data to force F: AAAAAAOOOOOOOOOAAAOAOAOAOAOAO, mmmmmmmmmmmmmmmmm")

	s1 := NewStrobe(t.Name())
	s2 := strobe.InitStrobe(t.Name(), SecLevel)

	s1.Ad([]byte(t.Name()), false)
	s1.Key(key, false)
	s1.Ad(data, false)
	s1.Ad(data, true)

	s2.AD(false, []byte(t.Name()))
	s2.KEY(key)
	s2.AD(false, data)
	s2.Operate(false, "AD", data, 0, true)

	elapse(t, t.Name()+"Mini", func() {
		s := NewStrobe(t.Name())
		s.Ad([]byte(t.Name()), false)
		s.Key(key, false)
		s.Ad(data, false)
		s.Ad(data, true)
	})

	elapse(t, t.Name()+"Mimo", func() {
		s := strobe.InitStrobe(t.Name(), SecLevel)
		s.AD(false, []byte(t.Name()))
		s.KEY(key)
		s.AD(false, data)
		s.Operate(false, "AD", data, 0, true)
	})

	t.Logf("position: %d", s1.pos)
	t.Logf("%+v", s1.state)
	t.Logf("%+v", getState(s2))
}

func TestClone(t *testing.T) {
	s1 := NewStrobe(t.Name())
	s1.Ad([]byte("we gonna clone "), false)
	s1.Ad([]byte("this strobe"), true)
	s1.Key([]byte("but first rekey"), false)

	s2 := s1.Clone()

	s1.Ad([]byte("check deep copy"), false)
	s2.Ad([]byte("check deep copy"), false)
	hash1, hash2 := make([]byte, 16), make([]byte, 16)
	s1.Prf(hash1, false)
	s2.Prf(hash2, false)

	t.Logf("hash1: %s", hex.EncodeToString(hash1))
	t.Logf("hash2: %s", hex.EncodeToString(hash2))
	assert.Equal(t, hash1, hash2)
}
