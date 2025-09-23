package mailbox

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Format represents the format of the mailbox
type Format string

const (
	Maildir       Format = "maildir"
	MaildirNested Format = "maildir-nested"
)

type Flag string

const (
	Seen     Flag = "seen"
	Answered Flag = "answered"
	Flagged  Flag = "flagged"
	Deleted  Flag = "deleted"
	Draft    Flag = "draft"
)

// Message represents an email message
type Message struct {
	Identifier   string
	MailboxName  string // Added mailbox name for nested maildir support
	Flags        []Flag
	Keywords     map[string]bool // converted JMAP keywords
	InternalDate int64
	Contents     []byte
}

// Entry represents a single mailbox with its files
type Entry struct {
	Name  string
	Files []string
}

// Mailbox represents a mailbox iterator for a single mailbox
type Mailbox struct {
	format     Format
	files      []string
	fileIdx    int
	Folder     string         // mailbox folder name
	keywordMap map[int]string // dovecot keyword ID to name mapping
}

// scanMailboxDir scans a single mailbox directory for message files
func scanMailboxDir(mailboxPath string) ([]string, error) {
	var files []string
	curFiles, _ := scanMaildirDir(filepath.Join(mailboxPath, "cur"))
	newFiles, _ := scanMaildirDir(filepath.Join(mailboxPath, "new"))
	files = append(files, curFiles...)
	files = append(files, newFiles...)
	return files, nil
}

// scanMaildirDir scans a maildir directory (cur/ or new/) for message files
func scanMaildirDir(dirPath string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return files, nil // Directory doesn't exist, return empty
		}
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, filepath.Join(dirPath, entry.Name()))
		}
	}
	return files, nil
}

// normalizeMailboxName converts maildir folder names to standard mailbox names
func normalizeMailboxName(dirName string) string {
	if !strings.HasPrefix(dirName, ".") {
		return "Inbox" // Root directory
	}
	return dirName[1:]
}

// parseDovecotKeywords parses a dovecot-keywords file and returns keyword ID to name mapping
func parseDovecotKeywords(keywordsPath string) (map[int]string, error) {
	keywords := make(map[int]string)

	data, err := os.ReadFile(keywordsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return keywords, nil // File doesn't exist, return empty map
		}
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse "ID Keyword" or just "Keyword" format
		parts := strings.Fields(line)
		if len(parts) == 2 {
			id := int(parts[0][0] - '0')
			keywords[id] = parts[1]
		} else {
			return nil, fmt.Errorf("invalid dovecot-keywords line: %s", line)
		}
	}

	return keywords, nil
}

// convertDovecotKeywordsToJMAP converts dovecot keywords to JMAP keywords
func convertDovecotKeywordsToJMAP(keywords []string) map[string]bool {
	jmapKeywords := make(map[string]bool)

	for _, keywordName := range keywords {
		switch strings.ToLower(strings.Replace(keywordName, "$", "", 1)) {
		case "recent":
			jmapKeywords["$recent"] = true
		case "important":
			jmapKeywords["$important"] = true
		case "phishing":
			jmapKeywords["$phishing"] = true
		case "junk":
			jmapKeywords["$junk"] = true
		case "nonjunk", "notjunk":
			jmapKeywords["$notjunk"] = true
		case "forwarded":
			jmapKeywords["$forwarded"] = true
		case "mdnsent":
			jmapKeywords["$mdnsent"] = true
		default:
			log.Printf("Unknown keyword: %s", keywordName)
		}
	}

	return jmapKeywords
}

// NewMailbox creates mailbox iterators for all mailboxes found
func NewMailbox(format Format, path string) ([]*Mailbox, error) {
	var mailboxes []*Mailbox

	switch format {
	case Maildir:
		mailbox, err := newMailbox(format, path)
		if err != nil {
			return nil, err
		}
		mailboxes = append(mailboxes, mailbox)

	case MaildirNested:
		if mailbox, err := newMailbox(format, path); err != nil {
			return nil, err
		} else {
			mailboxes = append(mailboxes, mailbox)
		}

		// Scan subdirectories starting with '.'
		subDirs, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}

		for _, subDir := range subDirs {
			if !subDir.IsDir() || !strings.HasPrefix(subDir.Name(), ".") {
				continue
			}

			mailboxName := normalizeMailboxName(subDir.Name())
			subPath := filepath.Join(path, subDir.Name())
			if mailbox, err := newMailbox(format, subPath); err != nil {
				return nil, err
			} else {
				mailbox.Folder = mailboxName
				mailboxes = append(mailboxes, mailbox)
			}
		}

	default:
		return nil, fmt.Errorf("unsupported mailbox format: %s", format)
	}

	return mailboxes, nil
}

func newMailbox(format Format, path string) (*Mailbox, error) {
	// Load dovecot keywords for root mailbox
	keywordMap, err := parseDovecotKeywords(filepath.Join(path, "dovecot-keywords"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse dovecot-keywords: %w", err)
	}

	files, err := scanMailboxDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to scan mailbox: %w", err)
	}

	return &Mailbox{
		format:     format,
		files:      files,
		fileIdx:    0,
		Folder:     "Inbox",
		keywordMap: keywordMap,
	}, nil
}

// Next returns the next message from the mailbox
func (m *Mailbox) Next() (*Message, error) {
	if m.fileIdx >= len(m.files) {
		return nil, io.EOF
	}

	filename := m.files[m.fileIdx]
	m.fileIdx++

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Parse flags and keywords from filename (maildir format)
	base := filepath.Base(filename)
	flags := []Flag{}
	keywords := []string{}

	// Maildir flags are after the second colon
	if colonIndex := strings.LastIndex(base, ":"); colonIndex != -1 {
		flagStr := base[colonIndex+1:]

		// Parse dovecot maildir flags
		// Basic flags: S(Seen), R(Answered), F(Flagged), T(Deleted), D(Draft)
		// Keywords: a-z(0-25)
		for _, char := range flagStr {
			switch char {
			case 'S':
				flags = append(flags, Seen)
			case 'R':
				flags = append(flags, Answered)
			case 'F':
				flags = append(flags, Flagged)
			case 'T':
				flags = append(flags, Deleted)
			case 'D':
				flags = append(flags, Draft)
			default:
				// Keywords: a-z = 0-25
				if char >= 'a' && char <= 'z' {
					keywordID := int(char - 'a')
					keyword, ok := m.keywordMap[keywordID]
					if ok {
						keywords = append(keywords, keyword)
					} else {
						log.Printf("Unknown keyword ID: %c", char)
					}
				}
			}
		}
	}

	// Convert dovecot keywords to JMAP keywords
	jmapKeywords := convertDovecotKeywordsToJMAP(keywords)

	return &Message{
		Identifier:   base,
		MailboxName:  m.Folder,
		Flags:        flags,
		Keywords:     jmapKeywords,
		InternalDate: 0, // Would need to parse from file or filename
		Contents:     contents,
	}, nil
}
