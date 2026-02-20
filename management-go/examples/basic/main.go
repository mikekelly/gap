package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	gap "github.com/mikekelly/gap/management-go"
)

func main() {
	serverURL := os.Getenv("GAP_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:9080"
	}

	// Create unauthenticated client to check status
	client := gap.NewClient(serverURL)

	ctx := context.Background()

	status, err := client.Status(ctx)
	if err != nil {
		log.Fatalf("Failed to get status: %v", err)
	}
	fmt.Printf("GAP Server v%s (initialized: %v)\n", status.Version, status.Initialized)

	if !status.Initialized {
		fmt.Println("Server not initialized. Run Init() first.")
		return
	}

	// Create authenticated client
	password := os.Getenv("GAP_PASSWORD")
	if password == "" {
		fmt.Println("Set GAP_PASSWORD to interact with initialized server")
		return
	}
	h := sha512.Sum512([]byte(password))
	passcode := hex.EncodeToString(h[:])

	authClient := gap.NewClient(serverURL, gap.WithPasscode(passcode))

	// List plugins
	plugins, err := authClient.ListPlugins(ctx)
	if err != nil {
		log.Fatalf("Failed to list plugins: %v", err)
	}
	fmt.Printf("Installed plugins: %d\n", len(plugins.Plugins))
	for _, p := range plugins.Plugins {
		fmt.Printf("  - %s\n", p.Name)
	}

	// List tokens
	tokens, err := authClient.ListTokens(ctx)
	if err != nil {
		log.Fatalf("Failed to list tokens: %v", err)
	}
	fmt.Printf("Agent tokens: %d\n", len(tokens.Tokens))
}
