#!/bin/bash

# CloudSentinel - Simulation Runner Script

# Set project root path
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=================================================="
echo "🛡️  CloudSentinel - Security Simulation Launcher"
echo "=================================================="
echo ""

# 1. Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Error: Docker is not running. Please start the Docker daemon."
    exit 1
fi
echo "✅ Docker daemon is running."

# 2. Check if LocalStack container is running
if ! docker ps | grep -q "localstack"; then
    echo "⏳ LocalStack is not running. Starting it via docker-compose..."
    docker-compose up -d
    echo "⚡ LocalStack started. Waiting for initialization..."
else
    echo "✅ LocalStack container is already running."
fi

# 3. Wait for LocalStack health check
ENDPOINT="http://localhost:4566"
echo "[*] Waiting for LocalStack API to be healthy..."
for i in {1..30}; do
    if curl -s "$ENDPOINT/_localstack/health" > /dev/null; then
        echo "✅ LocalStack is healthy and reachable."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "❌ Error: LocalStack was not reachable after 30 seconds."
        exit 1
    fi
    echo "[*] Retrying in 1s ($i/30)..."
    sleep 1
done

# 4. Ask the user if they want to provision using Terraform or Javascript script
echo ""
echo "Choose infrastructure provisioning method:"
echo "  [1] Terraform (infra/main.tf)"
echo "  [2] Javascript Script (setup-localstack.js)"
read -rp "Enter choice [1 or 2, default: 2]: " choice

choice=${choice:-2}

if [ "$choice" -eq 1 ]; then
    echo ""
    echo "[*] Provisioning infrastructure with Terraform..."
    cd "$PROJECT_DIR/infra"
    
    # Initialize Terraform if not done
    if [ ! -d ".terraform" ]; then
        terraform init
    fi
    
    # Apply Terraform plan
    terraform apply -auto-approve
    echo "✅ Terraform provisioning complete."
    cd "$PROJECT_DIR"
else
    echo ""
    echo "[*] Provisioning infrastructure with Javascript/AWS-SDK..."
    cd "$PROJECT_DIR/backend"
    npm run setup
    cd "$PROJECT_DIR"
fi

# 5. Execute the Mega-Simulation
echo ""
echo "🚀 Triggering Mega Security Simulation (10+ scenarios each)..."
cd "$PROJECT_DIR/backend"
npm run mega

echo ""
echo "=================================================="
echo "🎉 Mega Security Simulation Loaded Successfully!"
echo "=================================================="
echo "Open the dashboard (usually http://localhost:5173 or http://localhost:5174)"
echo "to observe, investigate, and remediate the simulated anomalies!"
echo "=================================================="
