#!/bin/bash

# Extracts a section from the .db_csv file from ibdiag tool

INPUT_FILE=$1
SECTION=$2
OUTPU_DIR=$3

UPPER_SECTION=$(echo $SECTION | tr '[:lower:]' '[:upper:]')

awk -v start=START_"$UPPER_SECTION" -v end=END_"$UPPER_SECTION" '$0 == start {f=1;next} $0 == end {f=0;exit} f' $INPUT_FILE > $OUTPU_DIR/$SECTION.csv
