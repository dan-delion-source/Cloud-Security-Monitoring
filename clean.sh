#!/bin/bash

echo "=================================="
echo "  Git/GitHub Cleanup Script"
echo "=================================="

PROJECT_DIR="$(pwd)"

echo "[*] Cleaning project: $PROJECT_DIR"

# Remove git repository data
if [ -d ".git" ]; then
    echo "[+] Removing .git directory..."
    rm -rf .git
else
    echo "[-] No .git directory found"
fi

# Remove common git/github related files
FILES=(
    ".gitignore"
    ".gitattributes"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "[+] Removing $file"
        rm -f "$file"
    fi
done

# Remove GitHub workflows
if [ -d ".github" ]; then
    echo "[+] Removing .github directory..."
    rm -rf .github
fi

# Remove git hooks leftovers
if [ -d ".git/hooks" ]; then
    echo "[+] Removing git hooks..."
    rm -rf .git/hooks
fi

echo
echo "[*] Optional credential cleanup"

# Remove GitHub credentials from credential manager
git credential-cache exit 2>/dev/null

# Remove stored GitHub credentials
rm -f ~/.git-credentials

# Remove SSH known host entry for github.com
ssh-keygen -R github.com 2>/dev/null

echo
echo "[✓] Git/GitHub cleanup completed."
echo "[!] Your project is now just a normal folder."
