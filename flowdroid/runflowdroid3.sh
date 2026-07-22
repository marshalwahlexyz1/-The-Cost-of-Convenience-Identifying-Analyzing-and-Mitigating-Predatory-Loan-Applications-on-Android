#!/bin/bash

# Set memory limits for Java
export JAVA_OPTS="-Xmx64g"

# Define paths
FLOWDROID_JAR="$(realpath ~/FlowDroid/soot-infoflow-cmd/soot-infoflow-cmd-jar-with-dependencies.jar)"
PLATFORM_PATH="$(realpath ~/android-sdk/platforms)"
SOURCES_FILE="$(realpath ~/sourcesandsinks/apps82dec12.txt)"
APK_FOLDER="$(realpath ~/apk_files/apps80)"
OUTPUT_FOLDER="$(realpath ~/apps82resultsflowdroid3dec12)"

# Ensure output directory exists
mkdir -p "$OUTPUT_FOLDER"

# Maximum time (in seconds) allowed for analyzing a single app
TIMEOUT_DURATION=1500  # 25 minutes (1500 seconds)

# Loop through APKs and analyze
for apk in "$APK_FOLDER"/*.apk; do
    if [ -f "$apk" ]; then
        filename=$(basename "$apk" .apk)

        # Skip if analysis already completed
        if [ -f "$OUTPUT_FOLDER/$filename.xml" ]; then
            echo "$filename.apk: Already analyzed"
            continue
        fi

        echo "Running analysis on $filename.apk"

        # Run FlowDroid analysis with a timeout
        timeout $TIMEOUT_DURATION java $JAVA_OPTS -jar "$FLOWDROID_JAR" \
            -a "$apk" \
            -p "$PLATFORM_PATH" \
            -s "$SOURCES_FILE" \
            -o "$OUTPUT_FOLDER/$filename.xml" \
            -pr fast \
            -nc \
            -ca FAST \
            -nt \
            -ls \
            -st 5 \
            -d \
            -cg SPARK \
            -i ALL \
            -ns \
            -ds CONTEXTFLOWSENSITIVE \
            -dt 300 \
            -ct 300 \
            -rt 600

        # Check if the analysis is still running (timed out)
        if [ $? -eq 124 ]; then
            echo "$filename.apk: Analysis timed out. Moving to next app."
            continue
        fi

        # Check for leaks in the output
        if [ -f "$OUTPUT_FOLDER/$filename.xml" ]; then
            if grep -q "<DataFlow" "$OUTPUT_FOLDER/$filename.xml"; then
                leaks=$(grep -c "<DataFlow" "$OUTPUT_FOLDER/$filename.xml")
                echo "$filename.apk: Found $leaks leaks"
            else
                echo "$filename.apk: No leaks found"
            fi
        else
            echo "$filename.apk: Analysis failed or no output generated."
        fi

        # Add a pause to prevent resource overuse
        sleep 5
    fi
done

echo "Analysis complete. Results saved in $OUTPUT_FOLDER."

