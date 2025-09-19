package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	jmapclient "github.com/jclab-joseph/stalwart-importer/pkg/jmap"
	"github.com/jclab-joseph/stalwart-importer/pkg/mailbox"
)

// JMAPClient represents a JMAP client using our pkg/jmap library
type JMAPClient struct {
	client     *jmapclient.Client
	username   string
	password   string
	mailboxIDs map[string]string // name -> id mapping
}

// NewJMAPClient creates a new JMAP client using our pkg/jmap library
func NewJMAPClient(baseURL, credentials string) *JMAPClient {
	cl := jmapclient.NewClient(baseURL, credentials)

	return &JMAPClient{
		client:     cl,
		mailboxIDs: make(map[string]string),
	}
}

// GetSession is not needed as the library client handles session initialization

// SetDefaultAccountID sets the default account ID
func (c *JMAPClient) SetDefaultAccountID(accountID string) {
	// This method is kept for compatibility but accountID is managed by pkg/jmap.Client
}

// GetAccountID gets the account ID for the given email using pkg/jmap.Client
func (c *JMAPClient) GetAccountID(email string) error {
	return c.client.GetAccountID(email)
}

// GetMailboxes gets the mailbox information for the account using pkg/jmap.Client
func (c *JMAPClient) GetMailboxes() error {
	return c.client.GetMailboxes()
}

// makeRequest is not needed as the library handles requests

// JMAPRequest and JMAPResponse are replaced by library types

// UploadBlob uploads a blob using pkg/jmap.Client
func (c *JMAPClient) UploadBlob(contents []byte) (string, error) {
	return c.client.UploadBlob(contents)
}

// ImportEmail imports an email via JMAP using pkg/jmap.Client
func (c *JMAPClient) ImportEmail(contents []byte, mailboxName string, keywords map[string]bool, receivedAt *int64) error {
	return c.client.ImportEmail(contents, mailboxName, keywords, receivedAt)
}

// ImportCommands represents the import commands
type ImportCommands struct {
	Messages *ImportMessages `json:"messages,omitempty"`
	Account  *ImportAccount  `json:"account,omitempty"`
}

// ImportMessages represents the messages import command
type ImportMessages struct {
	NumConcurrent *int                  `json:"num_concurrent,omitempty"`
	Format        mailbox.MailboxFormat `json:"format"`
	Account       string                `json:"account"`
	Path          string                `json:"path"`
}

// ImportAccount represents the account import command
type ImportAccount struct {
	NumConcurrent *int   `json:"num_concurrent,omitempty"`
	Account       string `json:"account"`
	Path          string `json:"path"`
}

// Execute executes the import command
func (cmd *ImportCommands) Execute(client *JMAPClient) error {
	if cmd.Messages != nil {
		return cmd.Messages.Execute(client)
	}
	return fmt.Errorf("no command specified")
}

// Execute executes the messages import
func (cmd *ImportMessages) Execute(client *JMAPClient) error {
	numConcurrent := runtime.NumCPU()
	if cmd.NumConcurrent != nil {
		numConcurrent = *cmd.NumConcurrent
	}

	fmt.Println("[1/4] Parsing mailbox...")

	box, err := mailbox.NewMailbox(cmd.Format, cmd.Path)
	if err != nil {
		return fmt.Errorf("failed to open mailbox: %w", err)
	}

	// For simplicity, assume single mailbox for now
	// In full implementation, handle multiple mailboxes

	fmt.Println("[2/4] Fetching existing mailboxes...")

	// Fetch existing mailboxes (simplified)
	// In full implementation, implement JMAP mailbox fetching

	fmt.Println("[3/4] Creating missing mailboxes...")

	// Create missing mailboxes (simplified)

	fmt.Println("[4/4] Importing messages...")

	totalImported := int64(0)
	failures := []string{}

	var wg sync.WaitGroup
	sem := make(chan struct{}, numConcurrent)

	for {
		msg, err := box.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("I/O error reading message: %v", err))
			continue
		}

		wg.Add(1)
		go func(msg *mailbox.Message) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Convert flags to JMAP keywords
			keywords := make(map[string]bool)
			for _, flag := range msg.Flags {
				switch flag {
				case "seen":
					keywords["$seen"] = true
				case "answered":
					keywords["$answered"] = true
				case "flagged":
					keywords["$flagged"] = true
				case "deleted":
					keywords["$deleted"] = true
				case "draft":
					keywords["$draft"] = true
				}
			}

			// For now, use a default mailbox name (Inbox)
			// In full implementation, this should be determined from the mailbox structure
			mailboxName := "Inbox"

			var receivedAt *int64
			if msg.InternalDate > 0 {
				receivedAt = &msg.InternalDate
			}

			// Retry logic
			maxRetries := 3
			for retry := 0; retry < maxRetries; retry++ {
				err := client.ImportEmail(msg.Contents, mailboxName, keywords, receivedAt)
				if err == nil {
					atomic.AddInt64(&totalImported, 1)
					fmt.Printf("Successfully imported message: %s\n", msg.Identifier)
					return
				}

				fmt.Printf("Failed to import message %s (attempt %d/%d): %v\n", msg.Identifier, retry+1, maxRetries, err)

				if retry < maxRetries-1 {
					// Exponential backoff
					time.Sleep(time.Duration(100*(1<<retry)) * time.Millisecond)
					continue
				}

				// Failed after all retries
				failures = append(failures, fmt.Sprintf("Failed to import message %s after %d attempts: %v", msg.Identifier, maxRetries, err))
			}
		}(msg)
	}

	wg.Wait()

	fmt.Printf("\n\nSuccessfully imported %d messages.\n", totalImported)

	if len(failures) > 0 {
		fmt.Printf("There were %d failures:\n", len(failures))
		for _, failure := range failures {
			fmt.Println(failure)
		}
	}

	return nil
}

func main() {
	// Global flags
	var (
		url         = flag.String("u", "", "Server base URL")
		urlLong     = flag.String("url", "", "Server base URL")
		credentials = flag.String("c", "", "Authentication credentials (user:password)")
		credLong    = flag.String("credentials", "", "Authentication credentials (user:password)")
		timeout     = flag.Int("t", 30, "Connection timeout in seconds")
		timeoutLong = flag.Int("timeout", 30, "Connection timeout in seconds")
	)

	// Parse flags
	flag.Parse()

	// Use long form if short form is empty
	if *url == "" && *urlLong != "" {
		url = urlLong
	}
	if *credentials == "" && *credLong != "" {
		credentials = credLong
	}
	if *timeout == 30 && *timeoutLong != 30 {
		timeout = timeoutLong
	}

	// Check required flags
	if *url == "" {
		log.Fatal("Server URL is required. Use -u or --url")
	}
	if *credentials == "" {
		log.Fatal("Credentials are required. Use -c or --credentials")
	}

	args := flag.Args()
	if len(args) < 2 {
		log.Fatal("Usage: stalwart-cli import <command> [options]")
	}

	// Skip "import" command
	command := args[1]
	args = args[1:]

	var cmd ImportCommands

	switch command {
	case "messages":
		if len(args) < 5 {
			log.Fatal("Usage: stalwart-cli import messages <num_concurrent> <format> <account> <path>")
		}
		numConcurrent, _ := strconv.Atoi(args[1])
		format := mailbox.MailboxFormat(args[2])
		account := args[3]
		path := args[4]
		cmd.Messages = &ImportMessages{
			NumConcurrent: &numConcurrent,
			Format:        format,
			Account:       account,
			Path:          path,
		}
	case "account":
		if len(args) < 4 {
			log.Fatal("Usage: stalwart-cli import account <num_concurrent> <account> <path>")
		}
		numConcurrent, _ := strconv.Atoi(args[1])
		account := args[2]
		path := args[3]
		cmd.Account = &ImportAccount{
			NumConcurrent: &numConcurrent,
			Account:       account,
			Path:          path,
		}
	default:
		log.Fatalf("Unknown command: %s", command)
	}

	client := NewJMAPClient(*url, *credentials)

	// Get account ID and mailbox information
	if err := client.GetAccountID(cmd.Messages.Account); err != nil {
		log.Fatalf("Failed to get account ID: %v", err)
	}

	if err := client.GetMailboxes(); err != nil {
		log.Fatalf("Failed to get mailboxes: %v", err)
	}

	session, err := client.client.GetSession()
	if err != nil {
		log.Fatalf("Failed to get session: %v", err)
	}

	fmt.Printf("Using account ID: %s\n", client.client.GetCurrentAccountID())
	fmt.Printf("API URL: %s\n", session.APIURL)
	fmt.Printf("Upload URL: %s\n", session.UploadURL)
	fmt.Printf("Available mailboxes: %v\n", client.client.GetMailboxIDs())

	if err := cmd.Execute(client); err != nil {
		log.Fatal(err)
	}
}
