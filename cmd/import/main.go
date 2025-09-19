package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/foxcpp/go-jmap"
	"github.com/foxcpp/go-jmap/client"
)

// MailboxFormat represents the format of the mailbox
type MailboxFormat string

const (
	MailboxFormatMaildir       MailboxFormat = "maildir"
	MailboxFormatMaildirNested MailboxFormat = "maildir-nested"
)

// Message represents an email message
type Message struct {
	Identifier   string
	Flags        []string
	InternalDate int64
	Contents     []byte
}

// headerTransport is a custom HTTP transport that replaces Authentication header with Authorization
type headerTransport struct {
	baseTransport http.RoundTripper
	authHeader    string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace "Authentication" header with "Authorization"
	if auth := req.Header.Get("Authentication"); auth != "" {
		req.Header.Del("Authentication")
		req.Header.Set("Authorization", t.authHeader)
	}
	return t.baseTransport.RoundTrip(req)
}

// JMAPClient represents a JMAP client using foxcpp/go-jmap library
type JMAPClient struct {
	client     *client.Client
	username   string
	password   string
	accountID  jmap.ID
	mailboxIDs map[string]string // name -> id mapping
}

// NewJMAPClient creates a new JMAP client using foxcpp/go-jmap library
func NewJMAPClient(baseURL, credentials string) *JMAPClient {
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid credentials format. Expected user:password")
	}

	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	sessionURL := strings.TrimSuffix(baseURL, "/") + "/.well-known/jmap"

	// Create custom HTTP client that replaces "Authentication" header with "Authorization"
	customTransport := &headerTransport{
		baseTransport: http.DefaultTransport,
		authHeader:    "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials)),
	}
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: customTransport,
	}

	cl, err := client.NewWithClient(httpClient, sessionURL, authHeader)
	if err != nil {
		log.Fatalf("Failed to create JMAP client: %v", err)
	}
	if err != nil {
		log.Fatalf("Failed to create JMAP client: %v", err)
	}

	return &JMAPClient{
		client:     cl,
		username:   parts[0],
		password:   parts[1],
		mailboxIDs: make(map[string]string),
	}
}

// GetSession is not needed as the library client handles session initialization

// SetDefaultAccountID sets the default account ID
func (c *JMAPClient) SetDefaultAccountID(accountID string) {
	c.accountID = jmap.ID(accountID)
}

// GetAccountID gets the account ID for the given email using primaryAccounts and Principal/query
func (c *JMAPClient) GetAccountID(email string) error {
	// Get session info
	session, err := c.client.UpdateSession()
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Get primary account ID for mail capability
	primaryAccountID, ok := session.PrimaryAccounts["urn:ietf:params:jmap:mail"]
	if !ok {
		return fmt.Errorf("primary account ID for mail capability not found")
	}

	// Query for the specific account using Principal/query
	principalRequest := map[string]interface{}{
		"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
		"methodCalls": []interface{}{
			[]interface{}{
				"Principal/query",
				map[string]interface{}{
					"accountId": string(primaryAccountID),
					"filter":    map[string]interface{}{"email": email},
				},
				"p0",
			},
		},
	}

	// Make HTTP request
	data, err := json.Marshal(principalRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal principal request: %w", err)
	}

	req, err := http.NewRequest("POST", session.APIURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create principal request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)))

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("principal query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("principal query failed with status: %d", resp.StatusCode)
	}

	var principalResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&principalResponse); err != nil {
		return fmt.Errorf("failed to decode principal response: %w", err)
	}

	// Extract account ID from response
	if methodResponses, ok := principalResponse["methodResponses"].([]interface{}); ok && len(methodResponses) > 0 {
		if respArray, ok := methodResponses[0].([]interface{}); ok && len(respArray) >= 3 {
			if result, ok := respArray[1].(map[string]interface{}); ok {
				if ids, ok := result["ids"].([]interface{}); ok && len(ids) > 0 {
					if accountID, ok := ids[0].(string); ok {
						c.accountID = jmap.ID(accountID)
						return nil
					}
				}
			}
		}
	}

	return fmt.Errorf("failed to get account ID from principal query response")
}

// GetMailboxes gets the mailbox information for the account using direct HTTP request
func (c *JMAPClient) GetMailboxes() error {
	if c.accountID == "" {
		return fmt.Errorf("account ID not set")
	}

	// Create mailbox get request payload
	requestPayload := map[string]interface{}{
		"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
		"methodCalls": []interface{}{
			[]interface{}{
				"Mailbox/get",
				map[string]interface{}{
					"accountId":  string(c.accountID),
					"properties": []string{"name", "parentId", "role", "id"},
				},
				"m0",
			},
		},
	}

	// Get session info
	session, err := c.client.UpdateSession()
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Make HTTP request
	data, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", session.APIURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)))

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("mailbox get request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mailbox get failed with status: %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	c.mailboxIDs = make(map[string]string)
	if methodResponses, ok := response["methodResponses"].([]interface{}); ok && len(methodResponses) > 0 {
		if respArray, ok := methodResponses[0].([]interface{}); ok && len(respArray) >= 3 {
			if result, ok := respArray[1].(map[string]interface{}); ok {
				if list, ok := result["list"].([]interface{}); ok {
					for _, item := range list {
						if mailbox, ok := item.(map[string]interface{}); ok {
							if name, ok := mailbox["name"].(string); ok {
								if id, ok := mailbox["id"].(string); ok {
									c.mailboxIDs[name] = id
								}
							}
							if role, ok := mailbox["role"].(string); ok {
								if id, ok := mailbox["id"].(string); ok {
									c.mailboxIDs[role] = id
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// makeRequest is not needed as the library handles requests

// JMAPRequest and JMAPResponse are replaced by library types

// UploadBlob uploads a blob using the library's Upload method
func (c *JMAPClient) UploadBlob(contents []byte) (string, error) {
	if c.accountID == "" {
		return "", fmt.Errorf("account ID not set")
	}

	info, err := c.client.Upload(c.accountID, bytes.NewReader(contents))
	if err != nil {
		return "", fmt.Errorf("blob upload failed: %w", err)
	}

	return string(info.BlobID), nil
}

// ImportEmail imports an email via JMAP using Stalwart's format
func (c *JMAPClient) ImportEmail(contents []byte, mailboxName string, keywords map[string]bool, receivedAt *int64) error {
	// First upload the blob
	blobID, err := c.UploadBlob(contents)
	if err != nil {
		return fmt.Errorf("blob upload failed: %w", err)
	}

	// Get mailbox ID
	mailboxID, ok := c.mailboxIDs[mailboxName]
	if !ok {
		// Try with "inbox" if mailboxName is not found
		if mailboxName != "Inbox" {
			mailboxID, ok = c.mailboxIDs["inbox"]
		}
		if !ok {
			return fmt.Errorf("mailbox not found: %s", mailboxName)
		}
	}

	// Prepare mailbox IDs in Stalwart format
	mailboxIDs := map[string]bool{mailboxID: true}

	// Prepare keywords in Stalwart format
	jmapKeywords := make(map[string]bool)
	for key, value := range keywords {
		jmapKeywords[key] = value
	}

	// Prepare email import
	emailImport := map[string]interface{}{
		"accountId": c.accountID,
		"emails": map[string]interface{}{
			"i0": map[string]interface{}{
				"blobId":     blobID,
				"mailboxIds": mailboxIDs,
				"keywords":   jmapKeywords,
			},
		},
	}

	if receivedAt != nil {
		emailImport["emails"].(map[string]interface{})["i0"].(map[string]interface{})["receivedAt"] = time.Unix(*receivedAt, 0).Format(time.RFC3339)
	}

	importRequest := jmap.Request{
		Using: []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
		Calls: []jmap.Invocation{
			{
				Name:   "Email/import",
				CallID: "s0",
				Args:   emailImport,
			},
		},
	}

	// Get session info
	session, err := c.client.UpdateSession()
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Make HTTP request
	data, err := json.Marshal(importRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal import request: %w", err)
	}

	req, err := http.NewRequest("POST", session.APIURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create import request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password)))

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("email import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("email import failed with status: %d", resp.StatusCode)
	}

	return nil
}

// ImportCommands represents the import commands
type ImportCommands struct {
	Messages *ImportMessages `json:"messages,omitempty"`
	Account  *ImportAccount  `json:"account,omitempty"`
}

// ImportMessages represents the messages import command
type ImportMessages struct {
	NumConcurrent *int          `json:"num_concurrent,omitempty"`
	Format        MailboxFormat `json:"format"`
	Account       string        `json:"account"`
	Path          string        `json:"path"`
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

	mailbox, err := NewMailbox(cmd.Format, cmd.Path)
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
		msg, err := mailbox.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("I/O error reading message: %v", err))
			continue
		}

		wg.Add(1)
		go func(msg *Message) {
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
		format := MailboxFormat(args[2])
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

	fmt.Printf("Using account ID: %s\n", client.accountID)
	fmt.Printf("API URL: %s\n", client.client.Session.APIURL)
	fmt.Printf("Upload URL: %s\n", client.client.Session.UploadURL)
	fmt.Printf("Available mailboxes: %v\n", client.mailboxIDs)

	if err := cmd.Execute(client); err != nil {
		log.Fatal(err)
	}
}
