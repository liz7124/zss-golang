package main

import (
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/Nik-U/pbc"
)

func main() {
	b, err := os.ReadFile("pbc-0.5.14.tar.gz") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}

	//fmt.Println(b) // print the content as 'bytes'

	message := string(b) // convert content to a 'string'

	//fmt.Println(str) // print the content as a 'string'

	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
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
	print("x=")
	print(x.String())
	print("\nP=")
	print(P.String())

	Ppub.MulZn(P, x)
	print("\nPpub=")
	print(Ppub.String())
	print("\nSIGN...\n")

	H.SetFromStringHash(message, sha256.New())
	print("H=")
	print(H.String())
	t1.Add(H, x)
	print("\nt1=")
	print(t1.String())
	t1.Invert(t1)
	S.MulZn(P, t1)
	//print(H)
	print("\nS = ")
	print(S.String())

	print("\nVERIFICATION\n")
	r := pairing.NewZr()
	r.Rand()
	print("r=")
	print(r.String())
	print("\n")

	temp := pairing.NewG1()
	delta := pairing.NewG1()
	temp.MulZn(P, H)
	temp.Add(temp, Ppub)
	delta.MulZn(temp, r)

	print("temp=")
	print(temp.String())
	print("\ndelta=")
	print(delta.String())

	omega := pairing.NewG1()
	omega.MulZn(S, r)

	t3 := pairing.NewGT()
	t3.Pair(delta, omega)
	print("\nt3=")
	print(t3.String())
	print("================================\nt4=")
	temp2 := pairing.NewG1()
	temp2.MulZn(P, r)
	t4 := pairing.NewGT()
	t4.Pair(temp2, temp2)
	print(t4.String())

	if !t3.Equals(t4) {
		print("Signature is invalid!\n")
	} else {
		print("Signature valid\n")
	}

}
