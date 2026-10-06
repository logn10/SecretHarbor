package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/secretharbor/secretharbor/internal/docs"
)

func main() {
	outDir := "man/man1"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output dir: %v\n", err)
		os.Exit(1)
	}

	// 1. Generate main shb.1 and secretharbor.1 alias
	mainMan := docs.GenerateMainManPage()
	mainPath := filepath.Join(outDir, "shb.1")
	if err := os.WriteFile(mainPath, []byte(mainMan), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", mainPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s\n", mainPath)

	aliasPath := filepath.Join(outDir, "secretharbor.1")
	if err := os.WriteFile(aliasPath, []byte(".so man1/shb.1\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing alias %s: %v\n", aliasPath, err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s (alias -> shb.1)\n", aliasPath)

	// 2. Generate command-specific man pages
	subPages := []string{
		"init", "adopt", "restart", "run", "status", "sessions", "stop", "config", "policy", "secret", "env", "restore", "trust", "doctor", "guard", "update", "version", "help",
	}

	for _, name := range subPages {
		pageContent, err := docs.GenerateCommandManPage(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating page for %s: %v\n", name, err)
			os.Exit(1)
		}
		path := filepath.Join(outDir, fmt.Sprintf("shb-%s.1", name))
		if err := os.WriteFile(path, []byte(pageContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", path)
	}

	fmt.Println("All man pages generated successfully.")
}
