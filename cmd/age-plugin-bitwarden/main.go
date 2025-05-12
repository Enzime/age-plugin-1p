package main

import (
	"log"

	"github.com/Enzyme/age-plugin-pwmanager/internal/pwmanager"
)

func main() {

	var example = `
  $ age-plugin-bitwarden --print-recipients
  ce3e36d1-271c-4019-9679-3244c41797e7 (person1@bitwarden): ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE


  $ echo "Hello World" | age -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINKZfejb9htpSB5K9p0RuEowErkba2BMKaze93ZVkQIE" > secret.age

  $ age --decrypt -j bitwarden -o - secret.age
  Hello World`

	backend := Bitwarden{}
	rootCmd := pwmanager.RootCmd(backend, example)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}

}
