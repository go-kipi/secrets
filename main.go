package secretman

import (
	"fmt"
	"os"

	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./secret <password> [set|get|list|delete] [key|key=value]")
		os.Exit(1)
	}

	password := os.Args[1]
	command := os.Args[2]
	args := os.Args[3:]

	store, err := Init(password)
	if err != nil {
		fmt.Println("Error initializing store:", err)
		os.Exit(1)
	}

	switch command {
	case "set":
		if len(args) < 1 || !strings.Contains(args[0], "=") {
			fmt.Println("Usage: set KEY=value")
			os.Exit(1)
		}
		parts := strings.SplitN(args[0], "=", 2)
		err := store.Set(parts[0], parts[1])
		if err != nil {
			fmt.Println("Error saving secret:", err)
		}
	case "get":
		if len(args) < 1 {
			fmt.Println("Usage: get KEY")
			os.Exit(1)
		}
		fmt.Println(store.Get(args[0]))
	case "delete":
		if len(args) < 1 {
			fmt.Println("Usage: delete KEY")
			os.Exit(1)
		}
		err := store.Delete(args[0])
		if err != nil {
			fmt.Println("Error deleting secret:", err)
		}
	case "list":
		for _, k := range store.ListKeys() {
			fmt.Println(k)
		}
	case "json":
		j, err := store.AsJSON()
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			fmt.Println(j)
		}
	default:
		fmt.Println("Unknown command:", command)
		os.Exit(1)
	}
}
