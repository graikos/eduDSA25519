package main

import (
	"ed/eddsa"
	"fmt"
)

func main() {
	msg := "hello"
	privkey, pubkey := eddsa.GenerateKeys()
	fmt.Printf("Secret key is: \n %x\n", privkey.Bytes())
	fmt.Printf("Public key is: \n %x\n", pubkey.Bytes())

	sig, err := eddsa.Sign(privkey, []byte(msg))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", sig)
}
