# Stalwart Importer

A tool for importing email messages from Dovecot maildir format into Stalwart Mail Server using the JMAP protocol.

## Features

### 📧 **Maildir Support**
- **maildir**: Standard maildir format
- **maildir-nested**: Hierarchical maildir with subfolders (e.g., `.Drafts/`, `.Trash/`)
- Automatic mailbox name normalization and mapping

### 🏷️ **Advanced Keyword Handling**
- **Dovecot Keywords**: Automatically parses `dovecot-keywords` files from each mailbox
- **JMAP Keywords**: Converts dovecot keywords to standard JMAP keywords:
  - `$forwarded` (from "Forwarded" or "$Forwarded")
  - `$junk` (from "Junk")
  - `$notjunk` (from "NonJunk" or "NotJunk")
- **Flag Parsing**: Correctly handles dovecot maildir flags including keyword combinations

### 🔄 **Smart Mailbox Mapping Support**
- User-defined mailbox name mapping with `--mailbox-map EXISTING=NEW` flag
- Automatic case-insensitive matching

### Pre-built Binaries
Download from the [releases page](https://github.com/jclab-joseph/stalwart-importer/releases).

## Usage

### Basic Import
```bash
./stalwart-import -u https://mail.example.com/jmap/session \
                  -c 'admin:password' \
                  messages maildir-nested user@example.com /path/to/maildir
```

### With Mailbox Mapping
```bash
./stalwart-import -u https://mail.example.com/jmap/session \
                  -c 'admin:password' \
                  --mailbox-map 'Archive.2025=Archive' \
                  messages maildir-nested user@example.com /path/to/maildir
```

## Command Line Options

### Global Options
- `-u, --url <URL>`: JMAP session endpoint URL (required)
- `-c, --credentials <user:pass>`: Authentication credentials (required)
- `-t, --timeout <seconds>`: Connection timeout in seconds (default: 30)

### Import Options
- `--mailbox-map <OLD=NEW>`: Map source mailbox name to destination mailbox name (can be used multiple times)

### Import Command
```
import messages <format> <account> <path>

Arguments:
  format            Mailbox format: maildir or maildir-nested
  account           Email address of the account to import into
  path              Path to the maildir directory
```

## Dovecot Keywords Support

The importer automatically reads `dovecot-keywords` files from each mailbox directory and converts them to JMAP keywords:

### dovecot-keywords file format:

```
0 $Forwarded
1 $MDNSent
2 Junk
3 NonJunk
```

### Supported JMAP Keywords:
- `$seen` - Message has been read
- `$answered` - Message has been answered
- `$flagged` - Message is flagged
- `$deleted` - Message is marked for deletion
- `$draft` - Message is a draft
- `$forwarded` - Message has been forwarded
- `$junk` - Message is classified as junk/spam
- `$notjunk` - Message is not junk/spam

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
