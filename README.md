Another feature-complete Go implementation of Merlin.

---
[Merlin][merlin_cool] is a STROBE-based transcript
construction for zero-knowledge proofs.\
Invented by Henry de Valence, Isis Lovecruft and Oleg Andreev.

[STROBE][strobe] is a tiny framework for cryptographic protocols
that uses only one block function — Keccak-f.\
Invented by Mike Hamburg.\
Presented [strobe.go](strobe/strobe.go) is partial implementation of strobe specs
needed for Merlin transcripts.

---
References:
* [dalek-cryptography/merlin][merlin_rs]
* [hdevalence/libmerlin][merlin_c]
* [gtank/merlin][merlin_go]

This project is licensed under the MIT license.

[merlin_cool]: https://merlin.cool
[strobe]: https://strobe.sourceforge.io/
[merlin_rs]: https://github.com/dalek-cryptography/merlin
[merlin_c]: https://github.com/hdevalence/libmerlin
[merlin_go]: https://github.com/gtank/merlin
