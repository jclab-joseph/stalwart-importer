package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Mailbox represents a mailbox iterator
type Mailbox struct {
	format MailboxFormat
	files  []string
	index  int
}

// NewMailbox creates a new mailbox iterator
func NewMailbox(format MailboxFormat, path string) (*Mailbox, error) {
	switch format {
	case MailboxFormatMaildir, MailboxFormatMaildirNested:
		var files []string

		// Scan cur/ directory for messages
		curDir := filepath.Join(path, "cur")
		entries, err := os.ReadDir(curDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read cur directory: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				files = append(files, filepath.Join(curDir, entry.Name()))
			}
		}

		// Scan new/ directory for messages
		newDir := filepath.Join(path, "new")
		entries, err = os.ReadDir(newDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read new directory: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				files = append(files, filepath.Join(newDir, entry.Name()))
			}
		}

		return &Mailbox{
			format: format,
			files:  files,
			index:  0,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported mailbox format: %s", format)
	}
}

// Next returns the next message from the mailbox
func (m *Mailbox) Next() (*Message, error) {
	if m.index >= len(m.files) {
		return nil, io.EOF
	}
	filename := m.files[m.index]
	m.index++

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
		Flags:        flags,
		InternalDate: 0, // Would need to parse from file or filename
		Contents:     contents,
	}, nil
}
