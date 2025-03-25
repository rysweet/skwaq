#!/bin/bash
set -e
echo "🧪 Running CI pipeline locally..."

# Check if venv exists and activate it
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "⚠️  Virtual environment not found, creating one..."
    python -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev,test]"
fi

echo "Running linting checks..."
python -m black --check .
python -m flake8 .
python -m mypy .
python -m pydocstyle ./skwaq

echo "Running unit tests..."
python -m pytest --cov=skwaq tests/

echo "Checking for documentation coverage..."
python -m docstr_coverage ./skwaq --fail-under=90

echo "Validating API docstrings..."
python -m pytest --doctest-modules ./skwaq

echo "Building documentation..."
cd docs && make clean html && cd ..

echo "Running milestone-specific tests..."
# Determine the current milestone based on code state
if [ -d "tests/milestones" ]; then
    for test_file in $(ls tests/milestones/test_*.py 2>/dev/null || echo ""); do
        echo "Running $test_file..."
        python -m pytest $test_file -v
    done
fi

# Run Docker validation
echo "Validating Docker build..."
docker build -t skwaq:local .
docker run --rm skwaq:local --version

echo "✅ Local CI completed successfully"