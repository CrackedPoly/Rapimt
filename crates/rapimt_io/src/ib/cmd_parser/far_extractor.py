#!/usr/bin/env python3

import os
import sys

# Check if the required arguments are provided
if len(sys.argv) != 3:
    print("Usage: python3 script.py ./ibdiagnet2.far(<input_file>) ./far/(<output_dir>)")
    sys.exit(1)

# Get the input file and output directory from the command-line arguments
input_file = sys.argv[1]
output_dir = sys.argv[2]

# Create the output directory if it doesn't exist
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
if not os.path.exists(os.path.join(output_dir, "group")):
    os.makedirs(os.path.join(output_dir, "group"))
if not os.path.exists(os.path.join(output_dir, "lft")):
    os.makedirs(os.path.join(output_dir, "lft"))

# Initialize the switch counter
switch_counter = 0

# Initialize the current switch ID
current_switch_id = ""

# Open the input file
with open(input_file, "r") as f:
    # Loop through the input file
    while line := next(f, None):
        # Check if the line starts with "Switch"
        if line.startswith("Switch"):
            # Extract the switch ID
            current_switch_id = line.split()[1]
            # Increment the switch counter
            switch_counter += 1

        # Check if the line starts with "Groups Definition:"
        elif line.startswith("Groups Definition:"):
            # Create the group definition CSV file
            group_file = os.path.join(output_dir, "group", f"{current_switch_id}.csv")
            # Write the header to the file
            with open(group_file, "w") as group_f:
                group_f.write("Group|SubGroup|WHBF|Ports\n")
                # move to records
                while line := next(f):
                    if line.startswith("------"):
                        break
                # Read the next lines until the next section
                while line := next(f):
                    if line[0].isdigit():
                        split_line = line.split()
                        if len(split_line) == 4:
                            group_f.write("|".join(split_line) + "\n")
                        else:
                            group_f.write("|".join(split_line[:3]) + "| \n")
                    else:
                        break

        # Check if the line starts with "LFT Definition:"
        elif line.startswith("LFT Definition:"):
            # Create the LFT definition CSV file
            lft_file = os.path.join(output_dir, "lft", f"{current_switch_id}.csv")
            # Write the header to the file
            with open(lft_file, "w") as lft_f:
                lft_f.write("LID|StaticPort|LidState|Group\n")
                while line := next(f):
                    if line.startswith("------"):
                        break
                while line := next(f):
                    if line[0].isdigit():
                        split_line = line.split()
                        lft_f.write("|".join(split_line) + "\n")
                    else:
                        break