package main

import (
	"fmt"
	"net/http"
	"reflect"
)

func main() {
	fmt.Println("The layout of net/http.Request (exported fields only):")

	typ := reflect.TypeOf(http.Request{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fmt.Printf(
			"%-20s offset: 0x%x, type: %-30s size: %d\n",
			field.Name,
			field.Offset,
			field.Type,
			field.Type.Size(),
		)
	}
}
