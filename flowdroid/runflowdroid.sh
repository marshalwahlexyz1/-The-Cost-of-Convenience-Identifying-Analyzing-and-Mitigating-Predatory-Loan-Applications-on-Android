#!/bin/bash

# Set memory limits for Java
export JAVA_OPTS="-Xmx128g" 

# Define paths
FLOWDROID_JAR="$(realpath ~/FlowDroid/soot-infoflow-cmd/soot-infoflow-cmd-jar-with-dependencies.jar)"
PLATFORM_PATH="$(realpath ~/android-sdk/platforms)"
SOURCES_FILE="$(realpath ~/sourcesandsinks/apps82.txt)"
APK_FOLDER="$(realpath ~/apk_files/apps80)"
OUTPUT_FOLDER="$(realpath ~/apps80results)"
LOG_FILE="$OUTPUT_FOLDER/leak_report.txt"

# Ensure output directory exists
mkdir -p "$OUTPUT_FOLDER"

# Initialize leak report log if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
    echo "Leak Analysis Report" > "$LOG_FILE"
fi

# Loop through APKs and analyze
for apk in "$APK_FOLDER"/*.apk; do
    if [ -f "$apk" ]; then
        filename=$(basename "$apk" .apk)
        
        # Skip if analysis already completed
        if [ -f "$OUTPUT_FOLDER/$filename.xml" ]; then
            echo "$filename.apk: Already analyzed" >> "$LOG_FILE"
            continue
        fi

        echo "Running analysis on $filename.apk"

        # Run FlowDroid analysis with timeouts
        java $JAVA_OPTS -jar "$FLOWDROID_JAR" \
            -a "$apk" \
            -p "$PLATFORM_PATH" \
            -s "$SOURCES_FILE" \
            -o "$OUTPUT_FOLDER/$filename.xml" \
            -pr fast \
            -nc \
	    -ca FAST\
	    -nt \
	    -lp \
            -ls \
	    -st 5 \
            -d \
            -cg SPARK \
	    -i ARRAYONLY \
            -dt 300 \
            -ct 300 \
            -rt 600 \
            2>&1 | tee "$OUTPUT_FOLDER/$filename.log"

        # Check for leaks in the output
        if grep -q "<DataFlow" "$OUTPUT_FOLDER/$filename.xml"; then
            leaks=$(grep -c "<DataFlow" "$OUTPUT_FOLDER/$filename.xml")
            echo "$filename.apk: Found $leaks leaks" >> "$LOG_FILE"
        else
            echo "$filename.apk: No leaks found" >> "$LOG_FILE"
        fi
    fi
done

echo "Analysis complete. Results saved in $OUTPUT_FOLDER and $LOG_FILE."

