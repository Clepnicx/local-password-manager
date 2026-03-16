# Local Password Manager

A simple command-line password manager that stores your passwords encrypted in a python shelve.

## Quick Start

### First-Time Setup

```bash
python3 pw.py
```

1. Create a new Master Password (remember it - there's no recovery!)
2. The database will be created automatically

## Dependencies

- `cryptography` - For encryption (Fernet)
- `stdiomask` - For secure password input

### Using Nix Shell

If you have Nix installed, you can run the program with all dependencies pre-configured:

```bash
cd local-password-manager

# Enter the nix shell with Python and required packages
nix-shell

# Then run the program inside the shell
python3 pw.py
```

Or use:

```bash
nix-shell --run "python3 pw.py"
```

## Commands

| Command | Description |
|---------|-------------|
| `save` | Store a new password entry |
| `call` | Retrieve a specific password |
| `list` | Show all stored accounts |
| `redo` | Edit or delete existing accounts |
| `q` | Quit the program |
