#!/bin/bash
set -e

echo "Setting up development environment for Skwaq..."

# Check OS and install dependencies
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Install Docker Desktop if not present
    if ! command -v docker &> /dev/null; then
        echo "Installing Docker Desktop..."
        brew install --cask docker
        echo "Please start Docker Desktop from the Applications folder"
        exit 1
    fi

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        echo "Docker is not running. Please start Docker Desktop from the Applications folder"
        exit 1
    fi

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if ! command -v docker &> /dev/null; then
        echo "Installing Docker..."
        curl -fsSL https://get.docker.com | sh
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo usermod -aG docker $USER
        echo "Please log out and back in for Docker permissions to take effect"
        exit 1
    fi
fi

# Install Python dependencies management tools
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    pip install uv
    echo "✅ uv installed"
else
    echo "✅ uv already installed"
fi

if ! command -v poetry &> /dev/null; then
    echo "Installing poetry..."
    pip install poetry
    echo "✅ poetry installed"
else
    echo "✅ poetry already installed"
fi

# Create and activate virtual environment
echo "Creating virtual environment..."
uv venv

# Install dependencies
echo "Installing project dependencies..."
poetry install --with dev

# Install pre-commit hooks
echo "Installing pre-commit hooks..."
poetry run pre-commit install

# Initialize Neo4j containers
echo "Starting Neo4j containers..."
docker compose up -d neo4j

echo "✅ Development environment setup complete!"
echo "Next steps:"
echo "1. Start working on the project"
echo "2. Run 'poetry shell' to activate the virtual environment"
echo "3. Run 'pre-commit run --all-files' to verify the setup"
