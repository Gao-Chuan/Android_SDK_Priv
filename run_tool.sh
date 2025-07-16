#!/bin/bash

# Check if an argument was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <apk_path_list>"
    exit 1
fi

# The input argument is the list of APK paths
apk_path_list="$1"

# Counter for progress tracking
counter=0

# Directory for log files
log_dir="./logs"

# Create the log directory if it doesn't exist
if [ ! -d "$log_dir" ]; then
    mkdir "$log_dir"
fi

# Read each line in the file
while IFS= read -r apk_path
do
    # Increment the counter
    counter=$((counter + 1))

    # Extract the APK filename (without the extension)
    apk_filename=$(basename "$apk_path" .apk)

    # Echo the APK path and progress
    echo "Processing APK #$counter: $apk_path"

    # Run the command with timeout, redirect output to log file in the logs directory
    timeout 7200 /N/project/android_lib_proj/privacy_impl/Privacy_implementation_flaws/static_analysis/gradlew run --args="$apk_path" >> "${log_dir}/${apk_filename}.log" 2>&1
done < "$apk_path_list"

