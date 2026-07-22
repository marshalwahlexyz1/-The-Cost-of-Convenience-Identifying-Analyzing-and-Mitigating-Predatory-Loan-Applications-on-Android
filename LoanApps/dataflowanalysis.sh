#!/bin/bash
#current code for data flow analysis as at Thursday Mar 27

#!/bin/bash

# Set memory limits for Java
export JAVA_OPTS="-Xmx256g"

# Define paths
FLOWDROID_JAR="/data/olawalea/FlowDroid/soot-infoflow-cmd/soot-infoflow-cmd-jar-with-dependencies.jar"
PLATFORM_PATH="/data/olawalea/android-sdk/platforms"
SOURCES_FILE="/data/olawalea/LoanApps/sourcesandsinks.txt"
APK_BASE_FOLDER="/data/olawalea/LoanApps/SensitiveAPIAnalysis"
OUTPUT_FOLDER="/data/olawalea/LoanApps/SensitiveAPIAnalysis/Results"
CSV_REPORT="/data/olawalea/LoanApps/SensitiveAPIAnalysis/Results/flowdroid_leak_summary.csv"

# Ensure output directory exists
mkdir -p "$OUTPUT_FOLDER"

# Initialize CSV report with headers
echo "App Name,Package Name,Country/Classification,Number of found leaks,Source API in leaks" > "$CSV_REPORT"

# Maximum time (in seconds) allowed for analyzing a single app
TIMEOUT_DURATION=1800  # 20 minutes

# Trap Ctrl+C to kill background processes gracefully
trap 'echo "Caught Ctrl+C, terminating..."; pids=$(jobs -p); [ -n "$pids" ] && kill -SIGTERM $pids; exit 1' SIGINT

process_apk() {
    local apk_path="$1"
    local country_class="$2"
    local apk="$3"
    local filename=$(basename "$apk" .apk)
    local output_file="$OUTPUT_FOLDER/$country_class/$filename.xml"
    local package_name=$(echo "$filename" | cut -d'_' -f1)

    mkdir -p "$OUTPUT_FOLDER/$country_class"

    if [ -f "$output_file" ]; then
        echo "$filename.apk: Already analyzed"
        return
    fi

    echo "Running analysis on $filename.apk ($country_class)"
    echo "Starting analysis for $apk_path at $(date)" | tee -a "$OUTPUT_FOLDER/flowdroid_errors.log"

    timeout -k 10 --foreground $TIMEOUT_DURATION java $JAVA_OPTS -jar "$FLOWDROID_JAR" \
        -a "$apk_path" \
        -p "$PLATFORM_PATH" \
        -s "$SOURCES_FILE" \
        -o "$output_file" \
        -pr fast \
        -dt 300 \
	-ct 300 \
        -d \
        -rt 600 2>&1 | tee -a "$OUTPUT_FOLDER/flowdroid_errors.log"

    if [ $? -eq 124 ]; then
        echo "$filename.apk: Analysis timed out after $TIMEOUT_DURATION seconds"
        echo "$filename,$package_name,$country_class,TIMED_OUT," >> "$CSV_REPORT"
        return
    elif [ $? -ne 0 ]; then
        echo "$filename.apk: Analysis failed (check log for details)"
        echo "$filename,$package_name,$country_class,FAILED," >> "$CSV_REPORT"
        return
    fi

    if [ -f "$output_file" ]; then
        if grep -q "</Results>" "$output_file"; then
            echo "XML output saved: $output_file"
            if grep -q "<DataFlow" "$output_file"; then
                leaks=$(grep -c "<DataFlow" "$output_file")
                echo "$filename.apk: Found $leaks leaks"
                sources=$(grep -oPm1 '(?<=<Source>).+?(?=</Source>)' "$output_file" | sort -u | paste -sd ";" -)
                echo "$filename,$package_name,$country_class,$leaks,\"$sources\"" >> "$CSV_REPORT"
            else
                echo "$filename.apk: No leaks found"
                echo "$filename,$package_name,$country_class,0," >> "$CSV_REPORT"
            fi
        else
            echo "Incomplete XML output for $filename.apk"
            echo "$filename,$package_name,$country_class,INCOMPLETE," >> "$CSV_REPORT"
        fi
    else
        echo "No XML output generated for $filename.apk - analysis failed"
        echo "$filename,$package_name,$country_class,FAILED," >> "$CSV_REPORT"
    fi
}

# Loop through all subdirectories in SensitiveAPIAnalysis
for country_folder in "$APK_BASE_FOLDER"/*; do
    if [ -d "$country_folder" ]; then
        country_class=$(basename "$country_folder")
        echo "Processing $country_class apps..."
        
        for apk in "$country_folder"/*.apk; do
            if [ -f "$apk" ]; then
                process_apk "$apk" "$country_class" "$apk"
                sleep 5  # Prevent resource overuse
            fi
        done
    fi
done

echo "Analysis complete. Results saved in $OUTPUT_FOLDER and summary in $CSV_REPORT"
