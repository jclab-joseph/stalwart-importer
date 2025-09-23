package mailbox

import (
	"fmt"
	"io"
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

// Message represents an email message
type Message struct {
	Identifier   string
	MailboxName  string // Added mailbox name for nested maildir support
	Flags        []string
	InternalDate int64
	Contents     []byte
}

// Entry represents a single mailbox with its files
type Entry struct {
	Name  string
	Files []string
}

// Mailbox represents a mailbox iterator that can handle multiple mailboxes
type Mailbox struct {
	format   Format
	entries  []Entry
	entryIdx int
	fileIdx  int
	Folders  []string
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

// NewMailbox creates a new mailbox iterator
func NewMailbox(format Format, path string) (*Mailbox, error) {
	var entries []Entry

	folders := []string{"Inbox"}

	switch format {
	case Maildir:
		files, err := scanMailboxDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to scan mailbox: %w", err)
		}
		entries = append(entries, Entry{Name: "Inbox", Files: files})

	case MaildirNested:
		// Scan root directory (Inbox)
		if rootFiles, err := scanMailboxDir(path); err == nil && len(rootFiles) > 0 {
			entries = append(entries, Entry{Name: "Inbox", Files: rootFiles})
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
			folders = append(folders, mailboxName)
			subPath := filepath.Join(path, subDir.Name())
			if subFiles, err := scanMailboxDir(subPath); err == nil && len(subFiles) > 0 {
				entries = append(entries, Entry{Name: mailboxName, Files: subFiles})
			}
		}

	default:
		return nil, fmt.Errorf("unsupported mailbox format: %s", format)
	}

	return &Mailbox{
		format:   format,
		entries:  entries,
		entryIdx: 0,
		fileIdx:  0,
		Folders:  folders,
	}, nil
}

// Next returns the next message from the mailbox
func (m *Mailbox) Next() (*Message, error) {
	// Find the next mailbox entry with files
	for m.entryIdx < len(m.entries) {
		entry := &m.entries[m.entryIdx]
		if m.fileIdx < len(entry.Files) {
			filename := entry.Files[m.fileIdx]
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

			// Parse flags from filename (maildir format)
			base := filepath.Base(filename)
			flags := []string{}

			// Maildir flags are after the second colon
			if colonIndex := strings.LastIndex(base, ":"); colonIndex != -1 {
				flagStr := base[colonIndex+1:]
				if strings.Contains(flagStr, "S") {
					flags = append(flags, "seen")
				}
				if strings.Contains(flagStr, "R") {
					flags = append(flags, "answered")
				}
				if strings.Contains(flagStr, "F") {
					flags = append(flags, "flagged")
				}
				if strings.Contains(flagStr, "T") {
					flags = append(flags, "deleted")
				}
				if strings.Contains(flagStr, "D") {
					flags = append(flags, "draft")
				}
			}

			return &Message{
				Identifier:   base,
				MailboxName:  entry.Name,
				Flags:        flags,
				InternalDate: 0, // Would need to parse from file or filename
				Contents:     contents,
			}, nil
		}

		// Move to next mailbox entry
		m.entryIdx++
		m.fileIdx = 0
	}

	return nil, io.EOF
}
