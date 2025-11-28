# Modern Docker-Based Deployment

This project uses a clean, modern, open-source-friendly deployment system based on:

- Docker Compose v2
- Environment files (`.env`)
- Modular bash scripts
- Optional Makefile shortcuts

## 🚀 Getting Started

### 1️⃣ Create your environment file

```bash
cp .env.example .env
```

Fill in required values.

### 2️⃣ Start the stack

```bash
docker compose up -d
```

or:

```bash
make up
```

### 3️⃣ Deploy (pull, build, restart)

```bash
make deploy
```

### 4️⃣ Run database migrations

```bash
make migrate
```

### 5️⃣ Backup database

```bash
make backup
```

### 6️⃣ Pull Cortex Analyzers

```bash
make analyzers
```

---

## 📂 Project Structure

- `docker-compose.yml` — main service orchestration
- `scripts/` — small, safe helper scripts
- `Makefile` — user-friendly commands
- `.env.example` — example config, safe to commit
- `.env` — actual config, **never commit**

---

## 🔐 Security Notes

- `.env` is in `.gitignore`
- place secrets here or use CI/CD secret injection
