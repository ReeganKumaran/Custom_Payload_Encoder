#!/bin/bash
# Helper script to extract obfuscated payload

if [ $# -ne 5 ]; then
    echo "Usage: $0 <file> <chain> <target> <variants> <output_file>"
    exit 1
fi

FILE="$1"
CHAIN="$2"
TARGET="$3"
VARIANTS="$4"
OUTPUT="$5"

# Run the framework and extract complete payload
python3 main.py --file "$FILE" --chain "$CHAIN" --target "$TARGET" --variants "$VARIANTS" 2>&1 | \
sed -n '/Ready for deployment:/,$ p' | \
tail -n +2 > "$OUTPUT"

# Check if extraction was successful
if [ -s "$OUTPUT" ]; then
    echo "✅ Payload extracted to: $OUTPUT"
    echo "📊 Size: $(wc -c < "$OUTPUT") bytes"
    echo "🔍 Preview: $(head -c 100 "$OUTPUT")..."
else
    echo "❌ Failed to extract payload"
    rm -f "$OUTPUT"
    exit 1
fi