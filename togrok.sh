#!/bin/bash

# This is a file that gather all code from the directory for easy use on Grok/any AI you use.
# Pretty hardcoded.

# Output file name
OUTPUT_FILE="code_contents.txt"

# Clear the output file if it exists, or create a new one
> "$OUTPUT_FILE"

# Function to append a file's contents with a header
append_file() {
    local file_path="$1"
    echo "===== $file_path =====" >> "$OUTPUT_FILE"
    cat "$file_path" >> "$OUTPUT_FILE"
    echo -e "\n" >> "$OUTPUT_FILE"
}

# Check if main.go exists and append its contents
if [ -f "main.go" ]; then
    append_file "main.go"
else
    echo "main.go not found!"
    exit 1
fi

# Check if public/ directory exists
if [ -d "public" ]; then
    # Find all files in public/ and append their contents
    find "public" -type f | while read -r file; do
        append_file "$file"
    done
else
    echo "public/ directory not found!"
    exit 1
fi

echo "Contents have been written to $OUTPUT_FILE"