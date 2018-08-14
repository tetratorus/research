package main

import (
	rand "crypto/rand"
	"fmt"
	"math/big"
	reflect "reflect"
	"unsafe"

	json "github.com/jgranstrom/go-simplejson"
	gonode "github.com/jgranstrom/gonodepkg"
	bn256 "golang.org/x/crypto/bn256"
)

func main() {
	// x, g1, gOneErr := bn256.RandomG1(rand.Reader)
	// fmt.Printf(fmt.Sprint(x), fmt.Sprint(g1), fmt.Sprint(gOneErr), "\n\n\n")
	// g1f := reflect.ValueOf(g1).Elem()
	// cP := g1f.FieldByName("p").Elem()
	// cPx := cP.FieldByName("x").Elem()
	// cPxi := reflect.NewAt(cPx.Type(), unsafe.Pointer(cPx.UnsafeAddr())).Elem().Interface().(big.Int)
	// fmt.Printf("\n\n\n\n\n")
	// fmt.Printf(cPxi.String())
	// fmt.Printf("\n")
	// // cPxrf := reflect.NewAt(cPx.Type(), unsafe.Pointer(cPx.UnsafeAddr())).Elem()
	// cPy := cP.FieldByName("y").Elem()
	// cPyi := reflect.NewAt(cPy.Type(), unsafe.Pointer(cPy.UnsafeAddr())).Elem().Interface().(big.Int)
	// fmt.Printf(cPyi.String())
	// fmt.Printf("\n")
	// // cPyrf := reflect.NewAt(cPy.Type(), unsafe.Pointer(cPy.UnsafeAddr())).Elem()
	// cPz := cP.FieldByName("z").Elem()
	// cPzi := reflect.NewAt(cPz.Type(), unsafe.Pointer(cPz.UnsafeAddr())).Elem().Interface().(big.Int)
	// fmt.Printf(cPzi.String())
	// fmt.Printf("\n")
	// // cPzrf := reflect.NewAt(cPz.Type(), unsafe.Pointer(cPx.UnsafeAddr())).Elem()
	// cPt := cP.FieldByName("t").Elem()
	// cPti := reflect.NewAt(cPt.Type(), unsafe.Pointer(cPt.UnsafeAddr())).Elem().Interface().(big.Int)
	// fmt.Printf(cPti.String())
	// fmt.Printf("\n")
	// // cPtrf := reflect.NewAt(cPt.Type(), unsafe.Pointer(cPx.UnsafeAddr())).Elem()
	// // fmt.Printf(fmt.Sprint(cPxrf), fmt.Sprint(cPyrf), fmt.Sprint(cPzrf), fmt.Sprint(cPtrf))
	gonode.Start(process)
}

func getX(g1 *bn256.G1) (s string) {
	g1f := reflect.ValueOf(g1).Elem()
	cP := g1f.FieldByName("p").Elem()
	cPx := cP.FieldByName("x").Elem()
	cPxi := reflect.NewAt(cPx.Type(), unsafe.Pointer(cPx.UnsafeAddr())).Elem().Interface().(big.Int)
	return cPxi.String()
}

func getY(g1 *bn256.G1) string {
	g1f := reflect.ValueOf(g1).Elem()
	cP := g1f.FieldByName("p").Elem()
	cPy := cP.FieldByName("y").Elem()
	cPyi := reflect.NewAt(cPy.Type(), unsafe.Pointer(cPy.UnsafeAddr())).Elem().Interface().(big.Int)
	return cPyi.String()
}

func getZ(g1 *bn256.G1) string {
	g1f := reflect.ValueOf(g1).Elem()
	cP := g1f.FieldByName("p").Elem()
	cPz := cP.FieldByName("z").Elem()
	cPzi := reflect.NewAt(cPz.Type(), unsafe.Pointer(cPz.UnsafeAddr())).Elem().Interface().(big.Int)
	return cPzi.String()
}

func getT(g1 *bn256.G1) string {
	g1f := reflect.ValueOf(g1).Elem()
	cP := g1f.FieldByName("p").Elem()
	cPt := cP.FieldByName("t").Elem()
	cPti := reflect.NewAt(cPt.Type(), unsafe.Pointer(cPt.UnsafeAddr())).Elem().Interface().(big.Int)
	return cPti.String()
}

func process(cmd *json.Json) (response *json.Json) {
	response, r, _ := json.MakeMap()
	data, d, _ := json.MakeMap()

	if cmd.Get("command").MustString() == "Hello there..." {
		r["response"] = "General Kenobi."
	} else if cmd.Get("command").MustString() == "generatePrivateKey" {
		x, g1, gOneErr := bn256.RandomG1(rand.Reader)
		if gOneErr != nil {
			r["response"] = "Failed when generating random point"
		} else {
			r["response"] = "Successfully generated a random point"
			r["data"] = data
			d["xG"] = fmt.Sprint(g1)
			d["x"] = x.String()
			d["xGX"] = getX(g1)
			d["xGY"] = getY(g1)
			d["xGZ"] = getZ(g1)
			d["xGT"] = getT(g1)
			// curvePt, cP, _ := json.MakeMap()
			// d["g1"] = curvePt
			// cP["p"] = g1.p
			// cP[""]
		}
	} else if cmd.Get("command").MustString() == "signMessage" {
		r["response"] = "Signing message function working"
	}

	return
}
