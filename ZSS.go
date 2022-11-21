package main

import (
	"crypto/sha256"

	"github.com/Nik-U/pbc"
)

// messageData represents a signed message sent over the network
type messageData struct {
	message   string
	signature []byte
}

func main() {
	params := pbc.GenerateA(160, 512)
	//pairing := params.NewPairing()

	// The authority distributes params and g to Alice and Bob
	sharedParams := params.String()

	// Channel for messages. Normally this would be a network connection.
	messageChannel := make(chan *messageData)

	// Channel for public key distribution. This might be a secure out-of-band
	// channel or something like a web of trust. The public key only needs to
	// be transmitted and verified once. The best way to do this is beyond the
	// scope of this example.
	keyChannel := make(chan []byte)

	generatorChannel := make(chan []byte)

	// Channel to wait until both simulations are done
	finished := make(chan bool)

	// Simulate the conversation participants
	go alice(sharedParams, messageChannel, keyChannel, generatorChannel, finished)
	go bob(sharedParams, messageChannel, keyChannel, generatorChannel, finished)

	// Wait for the communication to finish
	<-finished
	<-finished
}

// Alice generates a keypair and signs a message
func alice(sharedParams string, messageChannel chan *messageData, keyChannel chan []byte, generatorChannel chan []byte, finished chan bool) {
	// Alice loads the system parameters
	pairing, _ := pbc.NewPairingFromString(sharedParams)

	print("Parameter Initialization...\n")
	x := pairing.NewZr()
	H := pairing.NewZr()
	S := pairing.NewG1()
	P := pairing.NewG1()
	Ppub := pairing.NewG1()

	t1 := pairing.NewZr()

	print("KeyGen...\n")
	x.Rand()
	P.Rand()

	Ppub.MulZn(P, x)

	print("SIGN...\n")
	message := "some text to sign"
	//H := H.SetFromStringHash(message, sha256.New())
	H.SetFromStringHash(message, sha256.New())
	t1.Add(H, x)
	t1.Invert(t1)
	S.MulZn(P, t1)
	//print(H)
	print("S = ")
	print(S.String())

	// Send public key to Bob
	keyChannel <- Ppub.Bytes()

	// Send the message and signature to Bob
	messageChannel <- &messageData{message: message, signature: S.Bytes()}

	generatorChannel <- P.Bytes()

	finished <- true
}

// Bob verifies a message received from Alice
func bob(sharedParams string, messageChannel chan *messageData, keyChannel chan []byte, generatorChannel chan []byte, finished chan bool) {
	// Bob loads the system parameters
	pairing, _ := pbc.NewPairingFromString(sharedParams)

	//P := pairing.NewG1()
	t2 := pairing.NewG1()
	t3 := pairing.NewGT()
	t4 := pairing.NewGT()

	// Bob receives Alice's public key (and presumably verifies it manually)
	Ppub := pairing.NewG2().SetBytes(<-keyChannel)

	// Some time later, Bob receives a message to verify
	data := <-messageChannel
	S := pairing.NewG1().SetBytes(data.signature)
	P := pairing.NewG1().SetBytes(<-generatorChannel)

	print("\nVERIFY...\n")
	h := pairing.NewZr().SetFromStringHash(data.message, sha256.New())
	t2.MulZn(P, h)
	t2.Add(t2, Ppub)
	t3.Pair(t2, S)
	t4.Pair(P, P)
	if !t3.Equals(t4) {
		print("Signature is invalid!\n")
	} else {
		print("Signature valid\n")
	}

	finished <- true
}
