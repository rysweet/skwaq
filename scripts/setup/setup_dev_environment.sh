#!/bin/bash
set -e

echo "🚀 Setting up development environment for Skwaq..."

# Check if Python 3.10+ is installed
PYTHON_VERSION=$(python3 --version 2>/dev/null | cut -d' ' -f2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$PYTHON_MINOR" -lt 10 ]; then
    echo "❌ Python 3.10 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
else
    echo "✅ Python $PYTHON_VERSION detected"
fi

# Install uv if not installed
if ! command -v uv &> /dev/null; then
    echo "Installing uv package manager..."
    pip install uv
    echo "✅ uv installed"
else
    echo "✅ uv already installed"
fi

# Create virtual environment
echo "Creating virtual environment..."
uv venv
echo "✅ Virtual environment created"

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate
echo "✅ Virtual environment activated"

# Install dependencies using poetry
echo "Installing dependencies..."
if ! command -v poetry &> /dev/null; then
    echo "Installing poetry..."
    pip install poetry
    echo "✅ poetry installed"
else
    echo "✅ poetry already installed"
fi

poetry install
echo "✅ Dependencies installed"

# Install pre-commit hooks
echo "Setting up pre-commit hooks..."
pre-commit install
echo "✅ Pre-commit hooks installed"

# Check if Docker is installed (for Neo4j container)
if command -v docker &> /dev/null; then
    echo "✅ Docker is installed"
    
    # Check if docker-compose is installed
    if command -v docker-compose &> /dev/null; then
        echo "✅ docker-compose is installed"
    else
        echo "⚠️ docker-compose is not installed. You may need to install it to run Neo4j container."
    fi
    
    # Create directories for Neo4j data
    echo "Creating Neo4j data directories..."
    mkdir -p neo4j/data neo4j/logs neo4j/import neo4j/plugins
    echo "✅ Neo4j directories created"
    
    # Create docker-compose.yml file for Neo4j
    echo "Creating Neo4j docker-compose.yml file..."
    cat > docker-compose.yml << 'EOFDC'
version: '3'

services:
  neo4j:
    image: neo4j:latest
    container_name: skwaq-neo4j
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/skwaqpassword
      - NEO4J_apoc_export_file_enabled=true
      - NEO4J_apoc_import_file_enabled=true
      - NEO4J_apoc_import_file_use__neo4j__config=true
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*,gds.*
      - NEO4J_dbms_memory_heap_initial__size=1G
      - NEO4J_dbms_memory_heap_max__size=2G
    volumes:
      - ./neo4j/data:/data
      - ./neo4j/logs:/logs
      - ./neo4j/import:/import
      - ./neo4j/plugins:/plugins
EOFDC
    echo "✅ Neo4j docker-compose.yml created"
else
    echo "⚠️ Docker is not installed. You will need to install Docker to run Neo4j container."
fi

# Create initial config directory and file
echo "Creating initial configuration..."
mkdir -p config
cat > config/default_config.json << 'EOFC'
{
    "neo4j": {
        "uri": "bolt://localhost:7687",
        "user": "neo4j",
        "password": "skwaqpassword",
        "database": "neo4j"
    },
    "openai": {
        "api_type": "azure",
        "api_version": "2023-05-15"
    },
    "telemetry": {
        "enabled": true,
        "anonymous": true
    }
}
EOFC
echo "✅ Initial configuration created"

echo "Setting up local CI environment..."
# Create and make CI scripts executable
mkdir -p scripts/ci
cat > scripts/ci/run-local-ci.sh << 'EOFCI'
#!/bin/bash
set -e

echo "🧪 Running CI pipeline locally..."

# Check if venv exists and activate it
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "⚠️  Virtual environment not found, creating one..."
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

echo "✅ Local CI completed successfully"
EOFCI
chmod +x scripts/ci/run-local-ci.sh
echo "✅ Local CI environment setup completed"

# Create .gitignore file
echo "Creating .gitignore file..."
cat > .gitignore << 'EOFGI'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environment
.env
.venv
env/
venv/
ENV/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Project specific
neo4j/
config/azure_*.json
config/credentials.json

# Docker
.dockerignore

# Documentation
_build/
_static/
_templates/

# Logs
logs/
*.log
EOFGI
echo "✅ .gitignore created"

# Create .pre-commit-config.yaml
echo "Creating pre-commit configuration..."
cat > .pre-commit-config.yaml << 'EOFPC'
repos:
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
    -   id: trailing-whitespace
    -   id: end-of-file-fixer
    -   id: check-yaml
    -   id: check-added-large-files

-   repo: https://github.com/psf/black
    rev: 23.7.0
    hooks:
    -   id: black

-   repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
    -   id: flake8
        additional_dependencies: [flake8-docstrings]

-   repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
    -   id: mypy
        additional_dependencies: [types-requests]
EOFPC
echo "✅ Pre-commit configuration created"

echo "🎉 Development environment setup completed successfully!"
echo "To start Neo4j, run: docker-compose up -d neo4j"
echo "To activate the virtual environment, run: source .venv/bin/activate"
