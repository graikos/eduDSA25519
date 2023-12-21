package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"ed/services"
	"flag"
	"fmt"
	"os"
	"time"
)

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("keygen")
	fmt.Println("sign")
	fmt.Println("verify")
	fmt.Println("time")
	fmt.Println("help")
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("No command provided.")
		printHelp()
		os.Exit(0)
	}
	command := os.Args[1]

	switch command {
	case "sign":

		signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
		keyFile := signCmd.String("key", "", "Specifies the private key file")
		inputFile := signCmd.String("input", "", "Specifies the input file to be signed")

		signCmd.Parse(os.Args[2:])
		if *keyFile == "" || *inputFile == "" {
			fmt.Println("Not enough arguments provided.")
			os.Exit(1)
		}

		signer := services.NewSignService()
		keyReader := services.NewKeyReaderService()
		privKey, err := keyReader.ReadPrivatekey(*keyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = signer.SignFile(*inputFile, privKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)

	case "verify":

		verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
		keyFile := verifyCmd.String("pubkey", "", "Specifies the public key file")
		inputFile := verifyCmd.String("input", "", "Specifies the input file")
		sigFile := verifyCmd.String("signature", "", "Specifies the signature file to be verified")

		verifyCmd.Parse(os.Args[2:])
		if *keyFile == "" || *inputFile == "" || *sigFile == "" {
			fmt.Println("Not enough arguments provided.")
			os.Exit(1)
		}

		verifier := services.NewVerifyService()
		err := verifier.Verify(*inputFile, *keyFile, *sigFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Signature is valid.")
		os.Exit(0)

	case "keygen":
		keygenService := services.NewKeyGenerationService()
		if err := keygenService.GenerateKeys(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

	case "time":
		signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
		keyFile := signCmd.String("key", "", "Specifies the private key file")
		samples := signCmd.Int("samples", 10000, "Specifies the number of sample signatures used to measure time")

		signCmd.Parse(os.Args[2:])
		if *keyFile == "" {
			fmt.Println("Not enough arguments provided.")
			os.Exit(1)
		}

		signer := services.NewSignService()
		keyReader := services.NewKeyReaderService()
		privKey, err := keyReader.ReadPrivatekey(*keyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Initialize a slice of random messages of size 1kb each to be signed
		msgs := make([][]byte, 0, *samples)
		for i := 0; i < *samples; i++ {
			b := make([]byte, 1024)
			if n, err := rand.Read(b); n != 1024 || err != nil {
				fmt.Println("Error reading random bytes for dummy messages.")
				os.Exit(1)
			}
			msgs = append(msgs, b)
		}

		// Time the implementation's running time for the samples specified
		myNow := time.Now()
		for _, msg := range msgs {
			_, err := signer.SignBytes(msg, privKey)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		myTime := time.Since(myNow)

		// Time the standard library's implementation of ed25519
		stdKey := ed25519.NewKeyFromSeed(privKey.Bytes())
		stdNow := time.Now()
		for _, msg := range msgs {
			ed25519.Sign(stdKey, msg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		stdTime := time.Since(stdNow)

		fmt.Printf("Samples: %d\n", *samples)
		fmt.Printf("Implementation total time: %fs \n", time.Duration.Seconds(myTime))
		fmt.Printf("Standard library total time: %fs \n", time.Duration.Seconds(stdTime))
	case "help":
		printHelp()
	default:
		fmt.Println("Invalid command.")
		printHelp()
	}
}
