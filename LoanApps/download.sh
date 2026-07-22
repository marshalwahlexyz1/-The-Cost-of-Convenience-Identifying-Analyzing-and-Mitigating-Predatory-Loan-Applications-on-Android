#!/bin/bash

APIKEY="8ac6269f3a938b3d7def536e07471a2952364dd327dbcf21d2fc37ad1c616777"
CSV_FILE="found_packages.csv"

download_apk() {
    local package="$1"
    local sha256="$2"
    
    echo "Downloading $package..."
    curl -s -o "${package}.apk" -G \
        -d "apikey=$APIKEY" \
        -d "sha256=$sha256" \
        "https://androzoo.uni.lu/api/download"
    
    if [ -f "${package}.apk" ]; then
        if [ -s "${package}.apk" ]; then
            echo "✅ Success: $package"
        else
            echo "❌ Empty file: $package"
            rm -f "${package}.apk"
        fi
    else
        echo "❌ Failed: $package"
    fi
}

export -f download_apk
export APIKEY

# Improved CSV parsing with proper field quoting
tail -n +2 "$CSV_FILE" | \
awk -F',' '{gsub(/"/, ""); print $3 "," $4}' | \
xargs -P 20 -I {} bash -c '
    IFS="," read -r package sha256 <<< "{}"
    download_apk "$package" "$sha256"
'

echo "All downloads completed!"
