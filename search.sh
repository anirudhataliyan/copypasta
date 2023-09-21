#!/bin/bash
 
SEARCH_STRING="$1"
SEARCH_DIRECTORY="phrack"  # Change this to the root directory containing your files
 
# Using find to search through all subdirectories and filter .txt files
find "$SEARCH_DIRECTORY" -type f -name "*.txt" -exec grep -q "$SEARCH_STRING" {} \; -print
