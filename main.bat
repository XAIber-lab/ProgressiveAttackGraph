@echo off

echo "Start AG generation and analysis"

python src/main.py

echo "End generation... start analysis"

python src/plot_analysis.py

echo "End analysis"

exit