# Contributing to Suspicious

We welcome contributions to improve **Suspicious**, whether through new features, bug fixes, documentation, or optimizations.
This guide explains how to set up your development environment and submit changes via Pull Requests (PRs).

---

## Development Setup

Before contributing, ensure you have:

* [Git](https://git-scm.com/) installed
* A GitHub account
* A fork of the [official Suspicious repository](https://github.com/...)

Clone your fork locally:

```bash
git clone <your_forked_repository.git>
cd suspicious
```

Switch to a feature branch:

```bash
git checkout -b feature/<short_feature_name>
```

---

## Contribution Workflow

1. **Make changes** to the code or documentation.

2. **Stage files**:

   ```bash
   git add .
   ```

3. **Commit with a clear message**:

   ```bash
   git commit -m "feat: short title" -m "Optional longer description"
   ```

   * Use conventional commit style when possible:

     * `feat:` for a new feature
     * `fix:` for a bug fix
     * `docs:` for documentation changes
     * `refactor:` for code improvements without changing behavior

4. **Push your branch**:

   ```bash
   git push origin feature/<short_feature_name>
   ```

5. **Open a Pull Request (PR)** from your fork on GitHub:

   * Navigate to your repository
   * Click **Contribute > Open Pull Request**
   * Fill in the PR template (title, description, related issues)
   * Submit for review

---

## Code Review Process

* All PRs are reviewed by project maintainers.
* Reviews may request changes for consistency, security, or clarity.
* Once approved, your PR will be merged into the `dev` branch, then later into `main`.

---

## Best Practices

* Keep commits small and focused.
* Write clear commit messages.
* Ensure code is formatted and linted.
* Add/update tests where relevant.
* Update documentation when introducing changes.

---

✅ Following these steps helps us keep **Suspicious** reliable, maintainable, and secure.

---
