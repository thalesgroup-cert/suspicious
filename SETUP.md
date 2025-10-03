# Setup Guide

This document explains how to install and run **Suspicious** locally using Docker and Docker Compose.

---

## Prerequisites

Before starting, ensure you have the following installed on your system:

* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)
* [Git](https://git-scm.com/)

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/thalesgroup-cert/Suspicious.git
   ```

2. **Navigate to the project directory**

   ```bash
   cd suspicious
   ```

3. **Build the Docker containers**

   ```bash
   docker-compose build
   ```

4. **Start the containers**

   ```bash
   docker-compose up
   ```

The application will now be running at:
👉 [http://localhost:9020](http://localhost:9020)

---

## Usage

Once the environment is up and configured:

* **Web Interface**:
  Open [http://localhost:9020](http://localhost:9020) in your browser to access the platform.

* **Mail Submission**:
  Send a suspicious email as an attachment to the configured address (e.g., `suspicious@test.com`). The system will analyze and return results.

* **Web Form Submission**:
  Use the `Submit an Item` page to upload files, URLs, IPs, or hashes for analysis.

---

## Stopping the Application

To stop the containers, run:

```bash
docker-compose down
```

---

## Development Notes

* Make sure your branch is up-to-date with `dev` before building.
* Logs can be monitored with:

  ```bash
  docker-compose logs -f
  ```

* To rebuild after changes:

  ```bash
  docker-compose build --no-cache
  docker-compose up
  ```
