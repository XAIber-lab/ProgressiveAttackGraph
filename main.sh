#!/bin/bash

echo "Start AG generation and analysis"

python src/main.py
python src/plot_analysis.py

exit