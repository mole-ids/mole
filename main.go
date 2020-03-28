package main

import (
	"log"

	"github.com/jpalanco/mole/cmd"
)

func main() {
	if err := cmd.IDSCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}
