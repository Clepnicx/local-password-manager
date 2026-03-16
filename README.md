# Local Password Manager

A simple command-line password manager that stores your passwords encrypted on your computer.

## Quick Start

### First-Time Setup

```bash
python3 pw.py
```

1. Create a new Master Password (remember it - there's no recovery!)
2. The database will be created automatically

## Dependencies

This uses standard Python libraries plus:
- `cryptography` - For encryption (Fernet)
- `stdiomask` - For secure password input

Run with Python 3.7+

## Commands

| Command | Description |
|---------|-------------|
| `save` | Store a new password entry |
| `call` | Retrieve a specific password |
| `list` | Show all stored accounts |
| `redo` | Edit or delete existing accounts |
| `q` | Quit the program |
