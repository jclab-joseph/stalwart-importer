package jmap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/foxcpp/go-jmap"
	"github.com/foxcpp/go-jmap/client"
	mailbox2 "github.com/jclab-joseph/stalwart-importer/pkg/mailbox"
)

// PrincipalQueryRequest represents a Principal/query request
type PrincipalQueryRequest struct {
	Using       []string                   `json:"using"`
	MethodCalls []PrincipalQueryMethodCall `json:"methodCalls"`
}

// PrincipalQueryMethodCall represents a method call in Principal/query
type PrincipalQueryMethodCall struct {
	Name string             `json:"name"`
	Args PrincipalQueryArgs `json:"args"`
	ID   string             `json:"id"`
}

// PrincipalQueryArgs represents arguments for Principal/query
type PrincipalQueryArgs struct {
	AccountID string                 `json:"accountId"`
	Filter    map[string]interface{} `json:"filter"`
}

// PrincipalQueryResponse represents a Principal/query response
type PrincipalQueryResponse struct {
	MethodResponses []PrincipalQueryMethodResponse `json:"methodResponses"`
}

// PrincipalQueryMethodResponse represents a method response in Principal/query
type PrincipalQueryMethodResponse struct {
	Name string               `json:"name"`
	Args PrincipalQueryResult `json:"args"`
	ID   string               `json:"id"`
}

// PrincipalQueryResult represents the result of Principal/query
type PrincipalQueryResult struct {
	IDs []string `json:"ids"`
}

// MailboxGetRequest represents a Mailbox/get request
type MailboxGetRequest struct {
	Using       []string               `json:"using"`
	MethodCalls []MailboxGetMethodCall `json:"methodCalls"`
}

// MailboxGetMethodCall represents a method call in Mailbox/get
type MailboxGetMethodCall struct {
	Name string         `json:"name"`
	Args MailboxGetArgs `json:"args"`
	ID   string         `json:"id"`
}

// MailboxGetArgs represents arguments for Mailbox/get
type MailboxGetArgs struct {
	AccountID  string   `json:"accountId"`
	Properties []string `json:"properties"`
}

// MailboxGetResponse represents a Mailbox/get response
type MailboxGetResponse struct {
	MethodResponses []MailboxGetMethodResponse `json:"methodResponses"`
}

// MailboxGetMethodResponse represents a method response in Mailbox/get
type MailboxGetMethodResponse struct {
	Name string           `json:"name"`
	Args MailboxGetResult `json:"args"`
	ID   string           `json:"id"`
}

// MailboxGetResult represents the result of Mailbox/get
type MailboxGetResult struct {
	List []MailboxInfo `json:"list"`
}

// MailboxInfo represents mailbox information
type MailboxInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	ParentID string `json:"parentId,omitempty"`
	Role     string `json:"role,omitempty"`
}

// EmailImportRequest represents an Email/import request
type EmailImportRequest struct {
	Using       []string                `json:"using"`
	MethodCalls []EmailImportMethodCall `json:"methodCalls"`
}

// EmailImportMethodCall represents a method call in Email/import
type EmailImportMethodCall struct {
	Name string          `json:"name"`
	Args EmailImportArgs `json:"args"`
	ID   string          `json:"id"`
}

// EmailImportArgs represents arguments for Email/import
type EmailImportArgs struct {
	AccountID string                 `json:"accountId"`
	Emails    map[string]EmailImport `json:"emails"`
}

// EmailImport represents an email to import
type EmailImport struct {
	BlobID     string          `json:"blobId"`
	MailboxIDs map[string]bool `json:"mailboxIds"`
	Keywords   map[string]bool `json:"keywords"`
	ReceivedAt string          `json:"receivedAt,omitempty"`
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
	}
	req.Header.Set("Authorization", t.authHeader)
	return t.baseTransport.RoundTrip(req)
}

// Client represents a JMAP client using foxcpp/go-jmap library
type Client struct {
	client     *client.Client
	username   string
	password   string
	accountID  jmap.ID
	mailboxIDs map[string]string // name -> id mapping
}

// NewClient creates a new JMAP client using foxcpp/go-jmap library
func NewClient(baseURL, credentials string) *Client {
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

	return &Client{
		client:     cl,
		username:   parts[0],
		password:   parts[1],
		mailboxIDs: make(map[string]string),
	}
}

// SetDefaultAccountID sets the default account ID
func (c *Client) SetDefaultAccountID(accountID string) {
	c.accountID = jmap.ID(accountID)
}

// GetAccountID gets the account ID for the given email using primaryAccounts and Principal/query
func (c *Client) GetAccountID(email string) error {
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
func (c *Client) GetMailboxes() error {
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
									name, _ = mailbox2.DecodeIMAPUTF7(name)
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

// CreateMailbox creates a mailbox via JMAP Mailbox/set
func (c *Client) CreateMailbox(name string, parentID *string) (string, error) {
	if c.accountID == "" {
		return "", fmt.Errorf("account ID not set")
	}

	// Build request payload
	createArgs := map[string]interface{}{
		"accountId": string(c.accountID),
		"create": map[string]interface{}{
			"c0": map[string]interface{}{
				"name": name,
			},
		},
	}
	if parentID != nil && *parentID != "" {
		createArgs["create"].(map[string]interface{})["c0"].(map[string]interface{})["parentId"] = *parentID
	}

	session, err := c.client.UpdateSession()
	if err != nil {
		return "", fmt.Errorf("failed to get session: %w", err)
	}

	payload := map[string]interface{}{
		"using": []string{"urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"},
		"methodCalls": []interface{}{
			[]interface{}{
				"Mailbox/set",
				createArgs,
				"m0",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal mailbox create request: %w", err)
	}

	req, err := http.NewRequest("POST", session.APIURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create mailbox create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("mailbox create request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mailbox create failed with status: %d", resp.StatusCode)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode mailbox create response: %w", err)
	}

	if methodResponses, ok := response["methodResponses"].([]interface{}); ok && len(methodResponses) > 0 {
		if respArray, ok := methodResponses[0].([]interface{}); ok && len(respArray) >= 3 {
			if result, ok := respArray[1].(map[string]interface{}); ok {
				if created, ok := result["created"].(map[string]interface{}); ok {
					if c0, ok := created["c0"].(map[string]interface{}); ok {
						if id, ok := c0["id"].(string); ok {
							// Update local mailbox map as well
							c.mailboxIDs[name] = id
							return id, nil
						}
					}
				}
			}
		}
	}

	return "", fmt.Errorf("failed to parse mailbox create response")
}

// UploadBlob uploads a blob using the library's Upload method
func (c *Client) UploadBlob(contents []byte) (string, error) {
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
func (c *Client) ImportEmail(contents []byte, mailboxName string, keywords map[string]bool, receivedAt *int64) error {
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

// GetMailboxIDs returns the mailbox ID mapping
func (c *Client) GetMailboxIDs() map[string]string {
	return c.mailboxIDs
}

// GetCurrentAccountID returns the current account ID
func (c *Client) GetCurrentAccountID() jmap.ID {
	return c.accountID
}

// GetSession returns the JMAP session
func (c *Client) GetSession() (*jmap.Session, error) {
	return c.client.UpdateSession()
}
