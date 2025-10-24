package main

//go:noinline
func hello() {
	println("Hello, World!")
}

//go:noinline
func main() {
	for range 100 {
		hello()
	}
}
