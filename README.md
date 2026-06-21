# CloudSentinel - AWS Cloud Security Simulation & Dashboard

CloudSentinel is a comprehensive, local AWS security simulation and monitoring dashboard. It allows you to simulate cloud infrastructure provisioning, generate realistic security events (like unauthorized IAM access or unencrypted S3 buckets), and monitor them in a real-time React-based dashboard.

The entire environment runs locally using **LocalStack** to mock AWS services, meaning no real AWS accounts or costs are incurred.

## 🏗️ Project Architecture

- **LocalStack**: Mocks AWS services locally (`s3, lambda, dynamodb, sqs, sns, iam, sts, cloudtrail, ec2, secretsmanager`).
- **`/infra`**: Terraform configurations to provision the mocked AWS resources.
- **`/backend`**: Node.js scripts to trigger simulated security events (IAM anomalies, S3 misconfigurations, etc.) against the LocalStack environment.
- **`/dashboard`**: A React + Vite frontend application built with Tailwind CSS to visualize alerts, logs, and simulated anomalies.

## 🚀 Prerequisites

Ensure you have the following installed on your system:
- **Docker** and **Docker Compose** (required for LocalStack)
- **Node.js** (v18+ recommended) and **npm**
- **Terraform** (optional, if you want to use it for provisioning instead of the fallback JS script)

## 🛠️ Installation & Setup

1. **Clone the repository and install dependencies**
   First, install the node modules for both the frontend and backend:
   ```bash
   # Install Backend dependencies
   cd backend
   npm install

   # Install Dashboard dependencies
   cd ../dashboard
   npm install
   cd ..
   ```

2. **Start the Local Infrastructure & Simulations**
   We have provided an automated setup script that will start LocalStack, provision the infrastructure, and run a suite of security simulations.
   ```bash
   # Run the unified simulation script
   ./run-simulation.sh
   ```
   *Note: The script will prompt you to choose between Terraform or a Node.js script for provisioning. If you don't have Terraform installed, choose `2` (Javascript Script).*

3. **Start the Dashboard**
   Once the simulation is loaded, you can view the security events in the frontend dashboard.
   ```bash
   cd dashboard
   npm run dev
   ```
   Open your browser and navigate to `http://localhost:5173`.

## 🗂️ Running Specific Backend Simulations

If you want to manually trigger specific events instead of the mega-simulation, you can use the npm scripts in the `backend/` directory:

```bash
cd backend

# Provision infrastructure (if not using run-simulation.sh)
npm run setup

# Run a live continuous simulation
npm run live

# Run the mega simulation (spawns 10+ scenarios)
npm run mega
```

## 🔐 Security Note

This project is built for **educational and simulation purposes**. All AWS keys (e.g., `test` / `test`) used in this project are dummy keys configured to run strictly against local Docker containers via LocalStack. Do not insert your real production AWS credentials into this local setup.

## 🧹 Cleaning Up

To stop the LocalStack container and remove the provisioned data:
```bash
docker-compose down
```
