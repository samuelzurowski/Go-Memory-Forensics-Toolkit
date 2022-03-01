package main

// https://cujo.com/reverse-engineering-go-binaries-with-ghidra/

// https://medium.com/walmartglobaltech/de-ofuscating-golang-functions-93f610f4fb76

//     magic116 = {'0xfffffffa', '0xfaffffff'}
// find /b 0x400000, 0x525000, v

//lookup = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"
//lookup16 = "FF FF FF FA 00 00" if is_be else "FA FF FF FF 00 00"

import (
	"fmt"
)

type Object struct {
	Field int
}

func main() {
	A := Object{1}
	B := Object{2}
	fmt.Println(A, B)
	//fmt.Printf("A:%p;B:%p\n",&A,&B)
	//m := testStackOrHeap()
	//C:=m[A]
	//D:=m[B]
	//fmt.Printf("C:%p;D:%p\n",&C,&D)
}

//go:noinline
func testStackOrHeap() map[Object]Object {
	one := 1
	two := 2
	A := Object{one}
	B := Object{two}
	C := Object{one}
	D := Object{two}
	fmt.Println(C, D)
	fmt.Printf("A:%p;B:%p\n", &A, &B)
	m := map[Object]Object{A: A, B: B}
	return m
}
