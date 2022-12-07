package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Nik-U/pbc"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type sharedParams struct {
	x    []byte `json:"x"`
	P    []byte `json:"P"`
	Ppub []byte `json:"Ppub"`
}

func main() {
	//params := pbc.GenerateA(160, 512)
	//print("Params: ", params.String(), "\n")
	//pairing := params.NewPairing()

	pairingDesc := "type a\nq 5642758856946539409329201607468625461246274232051520707925217585926912195825269452922574408869582542622607831431906413907547311297381850113475181825328507\nh 7721864571087448110255505563247575626369455616111162536733439592888964433156808115647444665607966828952196\nr 730750818665534535851578973600197997769233793023\nexp2 159\nexp1 116\nsign1 1\nsign0 -1\n"
	pairing, _ := pbc.NewPairingFromString(pairingDesc)

	print("Parameter Initialization...\n")
	x := pairing.NewZr()
	P := pairing.NewG1()
	Ppub := pairing.NewG1()
	H := pairing.NewZr()
	S := pairing.NewG1()

	print("KeyGen...")
	/*x.Rand()
	P.Rand()
	Ppub.MulZn(P, x)
	print("x=")
	print(x.String())
	print("\nP=")
	print(P.String())
	print("\nPpub=")
	print(Ppub.String())*/

	/*write_P := []byte(P.CompressedBytes())
	filename := "sharedParams_P_bytes"
	//_, err := os.Create(filename)
	//check(err)

	err := ioutil.WriteFile(filename, write_P, 0666)
	check(err)

	write_x := []byte(x.String())
	filename = "sharedParams_X_bytes"
	err = ioutil.WriteFile(filename, write_x, 0666)
	check(err)

	write_Ppub := []byte(Ppub.CompressedBytes())
	filename = "sharedParams_Ppub_bytes"
	err = ioutil.WriteFile(filename, write_Ppub, 0666)
	check(err)*/

	read_P := "sharedParams_P_bytes"
	file, err := os.ReadFile(read_P)
	//print(string(file))
	check(err)

	P.SetCompressedBytes(file)
	print("P==")
	println(P.String())

	read_P = "sharedParams_X_bytes"
	file, err = os.ReadFile(read_P)
	//print(string(file))
	check(err)

	x.SetString(string(file), 10)
	print("x==")
	println(x.String())

	read_P = "sharedParams_Ppub_bytes"
	file, err = os.ReadFile(read_P)
	//print(string(file))
	check(err)

	Ppub.SetCompressedBytes(file)
	print("Ppub==")
	println(Ppub.String())

	delta := pairing.NewG1()
	omega := pairing.NewG1()
	r := pairing.NewZr()

	totalDataBlocks := int64(2)
	var r_array []string
	r_temp := pairing.NewZr()

	var s_array [][]byte
	s_temp := pairing.NewG1()

	var hash_array []string
	h_temp := pairing.NewZr()

	print("\nSIGN...\n")
	start := time.Now().UnixNano() / int64(time.Millisecond)
	for i := int64(0); i < totalDataBlocks; i++ {
		filename := "Files/part_" + strconv.FormatInt(i, 10)
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
		println(S.String())

		s_array = append(s_array, S.CompressedBytes())
	}
	stop := time.Now().UnixNano() / int64(time.Millisecond)
	elapsed := stop - start
	print("Sign time: ", elapsed, "\n")

	/*s_json, err := json.Marshal(s_array)
	check(err)
	print("json: ", string(s_json), "\n")

	write := []byte(string(s_json))
	filename := "S_json"
	ioutil.WriteFile(filename, write, 0666)*/

	/*print("\ns_array=")
	print(s_array[0])
	print("\n")*/

	read_P = "S_json"
	file, err = os.ReadFile(read_P)
	//print(string(file))
	check(err)
	var decoded [][]byte
	json.Unmarshal(file, &decoded)
	for i := int64(0); i < totalDataBlocks; i++ {
		s_temp.SetCompressedBytes(decoded[i])
		print("S==")
		println(s_temp.String())
	}

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

		//s_temp.SetString(s_array[i], 10)
		s_temp.SetCompressedBytes(s_array[i])
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
		//t4.Pair(P, P)

		if !t3.Equals(t4) {
			print("Signature is invalid!")
		} else {
			//print("Signature valid")
			print("-")
		}
	}
	verify_stop := time.Now().UnixNano() / int64(time.Millisecond)
	verify_duration := verify_stop - verify_start
	print("\nverification time: ", verify_duration)

}
