package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Nik-U/pbc"
)

func main() {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	print("Parameter Initialization...\n")
	x := pairing.NewZr()
	P := pairing.NewG1()
	Ppub := pairing.NewG1()
	H := pairing.NewZr()
	S := pairing.NewG1()

	print("KeyGen...")
	x.Rand()
	P.Rand()
	/*print("x=")
	print(x.String())
	print("\nP=")
	print(P.String())*/

	Ppub.MulZn(P, x)
	/*print("\nPpub=")
	print(Ppub.String())*/

	delta := pairing.NewG1()
	omega := pairing.NewG1()
	r := pairing.NewZr()

	totalDataBlocks := int64(100)
	var r_array []string
	r_temp := pairing.NewZr()

	var s_array []string
	s_temp := pairing.NewG1()

	var hash_array []string
	h_temp := pairing.NewZr()

	print("\nSIGN...\n")
	start := time.Now().UnixNano() / int64(time.Millisecond)
	for i := int64(0); i < totalDataBlocks; i++ {
		filename := "part_" + strconv.FormatInt(i, 10)
		b, err := os.ReadFile(filename) // just pass the file name
		if err != nil {
			fmt.Print(err)
		}

		message := string(b) // convert content to a 'string'

		t1 := pairing.NewZr()

		//print("\nSIGN...\n")

		H.SetFromStringHash(message, sha256.New())
		//print("Hash=", H.String(), "\n")

		hash_array = append(hash_array, H.String())

		t1.Add(H, x)
		//print(t1.String())
		t1.Invert(t1)
		S.MulZn(P, t1)
		//print(S.String())

		s_array = append(s_array, S.String())
	}
	stop := time.Now().UnixNano() / int64(time.Millisecond)
	elapsed := stop - start
	print("Sign time: ", elapsed, "\n")

	/*print("\ns_array=")
	print(s_array[0])
	print("\n")*/

	//verifier generate random r
	for i := int64(0); i < totalDataBlocks; i++ {
		r.Rand()
		/*print("r=")
		print(r.String())
		print("\n")*/

		r_array = append(r_array, r.String())
		/*print("r_array=")
		print(r_array[i])
		print("\n")*/
	}

	//CSP generate delta proof
	total_delta := pairing.NewG1()
	/*print("Total delta: ")
	print(total_delta.String())
	print("\n")*/
	var delta_array []string
	delta_temp := pairing.NewG1()
	csp_start := time.Now().UnixNano() / int64(time.Millisecond)
	for i := int64(0); i < totalDataBlocks; i++ {
		r_temp.SetString(r_array[i], 10)
		//print(r_temp.String(), "\n")

		temp := pairing.NewG1()
		h_temp.SetString(hash_array[i], 10)
		//print("hash_temp=", h_temp.String(), "\n")

		temp.MulZn(P, h_temp)
		temp.Add(temp, Ppub)
		delta.MulZn(temp, r_temp)

		total_delta.Add(total_delta, delta)
		delta_array = append(delta_array, delta.String())
		/*print("Total delta after add: ")
		print(total_delta.String())
		print("\n")*/

		/*print("temp=")
		print(temp.String())
		print("\ndelta=")
		print(delta.String())*/
	}
	csp_stop := time.Now().UnixNano() / int64(time.Millisecond)
	csp_duration := csp_stop - csp_start
	print("\nCSP proof delta computation time: ", csp_duration)

	//verifier generate omega and do verify the proof
	//total_omega := pairing.NewG1()
	//total_rp := pairing.NewG1()
	print("\nVERIFICATION...")
	verify_start := time.Now().UnixNano() / int64(time.Millisecond)
	for i := int64(0); i < totalDataBlocks; i++ {
		//print("\nVERIFICATION...")

		s_temp.SetString(s_array[i], 10)
		r_temp.SetString(r_array[i], 10)
		/*print(s_temp.String())
		print("\n", r_temp.String(), "\n")*/

		omega.MulZn(s_temp, r_temp)
		//total_omega.Add(total_omega, omega)

		/*rp_temp := pairing.NewG1()
		rp_temp.MulZn(P, r_temp)
		total_rp.Add(total_rp, rp_temp)*/

		t3 := pairing.NewGT()
		t4 := pairing.NewGT()

		delta_temp.SetString(delta_array[i], 10)

		t3.Pair(delta_temp, omega)
		/*print("\nt3=")
		print(t3.String())
		print("================================\nt4=")*/
		temp2 := pairing.NewG1()
		temp2.MulZn(P, r_temp)

		//t4.Pair(total_rp, total_rp)
		t4.Pair(temp2, temp2)
		//print(t4.String())

		if !t3.Equals(t4) {
			print("Signature is invalid!")
		} else {
			print("Signature valid")
		}
	}
	verify_stop := time.Now().UnixNano() / int64(time.Millisecond)
	verify_duration := verify_stop - verify_start
	print("\nverification time: ", verify_duration)

}
