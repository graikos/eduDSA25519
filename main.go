package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"ed/eddsa"
	"ed/services"
	"flag"
	"fmt"
	"os"
	"time"
)

func printHelp() {
	fmt.Println(helpMsg)
}

var helpMsg = `
Usage: ed <command> [options]

Commands:
  help     Displays help information about the commands.

  keygen   Generates a pair of PEM encoded key files.
           No additional options needed.

  sign     Signs a file using a PEM encoded private key.
           Options:
           -input <file>       Path to the file to be signed.
           -key <private_key>  Path to the PEM encoded private key file.

  verify   Verifies a signature of a file.
           Options:
           -input <file>        Path to the file for signature verification.
           -pubkey <public_key> Path to the PEM encoded public key file.
           -signature <sig>     Path to the PEM encoded signature file.

  time     Times the performance of the signing process against the standard library implementation.
           Options:
           -samples <number>    (Optional) Number of samples to be tested for timing. Default is 10000 if not specified.

For more details on each command, use: ed <command> --help

`

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
		samples := signCmd.Int("samples", 10000, "Specifies the number of sample signatures used to measure time")

		signCmd.Parse(os.Args[2:])

		signer := services.NewSignService()
		privKey := eddsa.NewPrivateKey()

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
		}
		stdTime := time.Since(stdNow)

		fmt.Printf("Samples: %d\n", *samples)
		fmt.Printf("Implementation total time: %fs \n", time.Duration.Seconds(myTime))
		fmt.Printf("Implementation average time: %fs \n", float64(time.Duration.Seconds(myTime))/float64(*samples))
		fmt.Printf("Standard library total time: %fs \n", time.Duration.Seconds(stdTime))
		fmt.Printf("Standard library average time: %fs \n", float64(time.Duration.Seconds(stdTime))/float64(*samples))
	case "help":
		printHelp()
	default:
		fmt.Println("Invalid command.")
		printHelp()
	}
}
