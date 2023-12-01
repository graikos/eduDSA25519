package eddsa

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
)

type PublicKey struct {
	point *edwards25519.Point
	raw   []byte
}

func (p *PublicKey) Bytes() []byte {
	return p.raw
}

func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	pk, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		pk,
		pk.Bytes(),
	}, nil
}

type PrivateKey struct {
	key []byte

	s         *edwards25519.Scalar
	publicKey *PublicKey

	h []byte
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) computeH() {
	tempH := sha512.Sum512(p.key)
	p.h = tempH[:]
}

func (p *PrivateKey) getPrefix() []byte {
	if p.h == nil {
		p.computeH()
	}
	return p.h[32:64]
}

func (p *PrivateKey) computeS() error {
	if p.h == nil {
		p.computeH()
	}
	s, err := new(edwards25519.Scalar).SetBytesWithClamping(p.h[:32])
	if err != nil {
		return fmt.Errorf("computing S: %v", err)
	}
	p.s = s
	return nil
}

func GenerateKeys() (*PrivateKey, *PublicKey) {
	p := NewPrivateKey()
	return p, p.publicKey
}

func (p *PrivateKey) computePublicKey() {
	if p.s == nil {
		p.computeS()
	}
	b := new(edwards25519.Point)
	b.ScalarBaseMult(p.s)
	p.publicKey = &PublicKey{
		b,
		b.Bytes(),
	}
}

func NewPrivateKey() *PrivateKey {
	k := make([]byte, 32)
	n, err := rand.Reader.Read(k)
	if err != nil {
		panic(err)
	}
	if n != 32 {
		panic("Could not generate 32 random bytes for key gen.")
	}

	privKey := &PrivateKey{key: k}
	privKey.key = k
	// all required intermediate values will be computed in the process of
	// computing the public key
	privKey.computePublicKey()

	return privKey
}

func Sign(privKey *PrivateKey, msg []byte) ([]byte, error) {
	// concat the second part of the digest h with the message
	// dom2(F, C) is empty string in ed25519
	rInput := make([]byte, 0, 32+len(msg))
	rInput = append(rInput, privKey.getPrefix()...)
	rInput = append(rInput, msg...)
	rsum := sha512.Sum512(rInput)

	rscalar, err := new(edwards25519.Scalar).SetUniformBytes(rsum[:])
	if err != nil {
		return nil, err
	}

	R := new(edwards25519.Point).ScalarBaseMult(rscalar)

	kInput := make([]byte, 0, 64+len(msg))
	kInput = append(kInput, R.Bytes()...)
	kInput = append(kInput, privKey.publicKey.raw...)
	kInput = append(kInput, msg...)
	ksum := sha512.Sum512(kInput)

	k, err := new(edwards25519.Scalar).SetUniformBytes(ksum[:])
	if err != nil {
		return nil, err
	}

	S := k.MultiplyAdd(k, privKey.s, rscalar)

	return append(R.Bytes(), S.Bytes()...), nil
}

func Verify(sig, msg, pubkeyBytes []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("invalid signature length")
	}
	pk, err := PublicKeyFromBytes(pubkeyBytes)
	if err != nil {
		return err
	}

	// first half of signature is R
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return err
	}

	// second half is S
	S, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return err
	}

	kInput := make([]byte, 0, len(msg)+64)
	kInput = append(kInput, sig[:32]...)
	kInput = append(kInput, pubkeyBytes...)
	kInput = append(kInput, msg...)
	ksum := sha512.Sum512(kInput)

	k, err := new(edwards25519.Scalar).SetUniformBytes(ksum[:])
	if err != nil {
		return err
	}

	// [S]B and then multiply by [8]
	firstPoint := new(edwards25519.Point).ScalarBaseMult(S)
	firstPoint.MultByCofactor(firstPoint)

	R.MultByCofactor(R)
	pk.point.ScalarMult(k, pk.point)
	pk.point.MultByCofactor(pk.point)

	R.Add(R, pk.point)

	if firstPoint.Equal(R) != 1 {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
