#!/bin/bash

# Execute the Python script. This script is expected to generate a .pyc file.
echo "--- 1. Executing Python Script to Generate .pyc ---"
python solve2.py

# # Check if the .pyc file was successfully created
# if [ -f genetic_sequencer.pyc ]; then
#     echo "--- 2. Decompiling genetic_sequencer.pyc ---"
    
#     # Run uncompyle6 on the generated .pyc file and pipe output to a new file
#     uncompyle6 genetic_sequencer.pyc > genetic_sequencer_source.py
    
#     echo "--- 3. Decompilation Complete. Contents of Source Code: ---"
#     # Print the resulting source code to the console
#     cat genetic_sequencer_source.py
# else
#     echo "❌ Error: genetic_sequencer.pyc was not found after script execution."
#     exit 1
# fi