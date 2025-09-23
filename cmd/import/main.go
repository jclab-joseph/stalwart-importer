package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jmapclient "github.com/jclab-joseph/stalwart-importer/pkg/jmap"
	"github.com/jclab-joseph/stalwart-importer/pkg/mailbox"
)

// MailboxMapping represents a single mailbox mapping rule
type MailboxMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type StringArray []string

func (s *StringArray) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *StringArray) String() string {
	return fmt.Sprintf("%v", *s)
}

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
	NumConcurrent *int           `json:"num_concurrent,omitempty"`
	Format        mailbox.Format `json:"format"`
	Account       string         `json:"account"`
	Path          string         `json:"path"`
	// MailboxMap Source(old) to Target(server)
	MailboxMap map[string]string `json:"mailbox_map,omitempty"`
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

// determineMailboxName determines the mailbox name from the mailbox path
func (cmd *ImportMessages) determineMailboxName(mailboxPath string) string {
	// For maildir format, the mailbox name is typically the directory name
	// Remove trailing slashes and get the last directory component
	cleanPath := strings.TrimRight(mailboxPath, "/")
	parts := strings.Split(cleanPath, "/")
	if len(parts) > 0 {
		dirName := parts[len(parts)-1]
		// Common mailbox names
		switch strings.ToLower(dirName) {
		case "inbox", "cur", "new", "tmp":
			return "Inbox"
		default:
			// If it looks like a UUID or data directory, default to Inbox
			if len(dirName) == 36 && strings.Contains(dirName, "-") {
				return "Inbox"
			}
			// If it's a data directory or unknown, default to Inbox
			if strings.HasPrefix(dirName, "data") || len(dirName) < 3 {
				return "Inbox"
			}
			return dirName
		}
	}
	return "Inbox"
}

// mapMailbox maps a source mailbox name to a destination mailbox name
func (cmd *ImportMessages) mapMailbox(sourceMailbox string, serverMailboxes map[string]string) string {
	// First, try exact name match
	if _, exists := serverMailboxes[sourceMailbox]; exists {
		return sourceMailbox
	}

	// Try case-insensitive match
	for serverName := range serverMailboxes {
		if strings.EqualFold(sourceMailbox, serverName) {
			return serverName
		}
	}

	mapped, ok := cmd.MailboxMap[sourceMailbox]
	if ok {
		return mapped
	}

	return ""
}

// Execute executes the messages import
func (cmd *ImportMessages) Execute(client *JMAPClient) error {
	numConcurrent := runtime.NumCPU()
	if cmd.NumConcurrent != nil {
		numConcurrent = *cmd.NumConcurrent
	}

	fmt.Println("[1/4] Parsing mailbox...")

	boxes, err := mailbox.NewMailbox(cmd.Format, cmd.Path)
	if err != nil {
		return fmt.Errorf("failed to open mailbox: %w", err)
	}

	fmt.Println("[2/4] Fetching existing mailboxes...")

	// Get server mailbox list
	serverMailboxes := client.client.GetMailboxIDs()
	fmt.Printf("Server mailboxes: %v\n", serverMailboxes)

	fmt.Println("[3/4] Checking mailboxes...")

	// Check all mailboxes found
	for _, box := range boxes {
		target := cmd.mapMailbox(box.Folder, serverMailboxes)
		if target == "" {
			log.Fatalf("Mailbox '%s' not found on server\n", box.Folder)
		}
	}

	fmt.Println("[4/4] Importing messages...")

	totalImported := int64(0)
	failures := []string{}

	var wg sync.WaitGroup
	sem := make(chan struct{}, numConcurrent)

	// Process each mailbox
	for _, box := range boxes {
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

				// Merge JMAP keywords from dovecot keywords (already converted in mailbox package)
				for k, v := range msg.Keywords {
					keywords[k] = v
				}

				// Use mailbox name from the message (for nested maildir support)
				sourceMailboxName := msg.MailboxName
				// Map to server mailbox name
				mailboxName := cmd.mapMailbox(sourceMailboxName, serverMailboxes)

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
	var mailboxMapStrs StringArray
	var (
		url           = flag.String("u", "", "Server base URL")
		urlLong       = flag.String("url", "", "Server base URL")
		credentials   = flag.String("c", "", "Authentication credentials (user:password)")
		credLong      = flag.String("credentials", "", "Authentication credentials (user:password)")
		timeout       = flag.Int("t", 30, "Connection timeout in seconds")
		timeoutLong   = flag.Int("timeout", 30, "Connection timeout in seconds")
		numConcurrent = flag.Int("concurrent", 4, "Number of concurrent requests")
	)
	flag.Var(&mailboxMapStrs, "mailbox-map", "Mailbox mapping in format OLD=NEW")

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
	if len(args) < 1 {
		log.Fatal("Usage: stalwart-import <command> [options]")
	}

	// Skip "import" command
	command := args[0]
	args = args[1:]

	var cmd ImportCommands

	switch command {
	case "messages":
		if len(args) < 3 {
			log.Fatal("Usage: stalwart-import messages <format> <account> <path>")
		}
		format := mailbox.Format(args[0])
		account := args[1]
		path := args[2]
		// Parse mailbox mapping
		mailboxMap := make(map[string]string, len(mailboxMapStrs))
		for _, str := range mailboxMapStrs {
			parts := strings.Split(str, "=")
			if len(parts) == 2 {
				mailboxMap[parts[0]] = parts[1]
			} else {
				log.Fatalf("Invalid mailbox-map format. Expected OLD=NEW, got: %s", str)
			}
		}

		cmd.Messages = &ImportMessages{
			NumConcurrent: numConcurrent,
			Format:        format,
			Account:       account,
			Path:          path,
			MailboxMap:    mailboxMap,
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
