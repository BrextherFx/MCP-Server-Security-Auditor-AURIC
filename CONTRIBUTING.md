# Contributing to MCP Server Security Auditor

Thank you for your interest in contributing to **MCP Server Security Auditor**! We are committed to building an open, transparent, and robust security toolkit for the Model Context Protocol ecosystem.

This project is licensed under the **[MIT License](LICENSE)**. By contributing, you agree that your contributions will be licensed under its terms.

---

## 🧭 How You Can Contribute

1. **New Static AST Rules**: Add detectors for newly discovered MCP vulnerability patterns in `mcpaudit/static_scanner.py`.
2. **Prompt Injection / Tool Poisoning Vectors**: Expand adversarial prompts and detection heuristics in `mcpaudit/desc_analyzer.py`.
3. **Dynamic Probes**: Add non-destructive, fuzzing, or boundary-testing probes in `mcpaudit/dynamic_prober.py`.
4. **Remediation Code Patches**: Enrich actionable Before/After code patches in `mcpaudit/report_engine.py`.
5. **Dashboard Enhancements**: Improve the Tailwind CSS & FastAPI interactive web console in `mcpaudit/web_app.py`.
6. **Documentation & Guides**: Clarify explanations, add usage examples, or refine setup instructions.

---

## 🛠️ Local Development Setup

### 1. Prerequisites
- Python 3.10+ (Python 3.12 recommended)
- Git
- Optional: Docker Desktop / Docker Engine

### 2. Fork & Clone
```bash
git clone https://github.com/mcp-security/mcpaudit.git
cd mcpaudit
```

### 3. Create Virtual Environment
```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"  # or pip install -e .
pip install pytest pytest-asyncio
```

---

## 🧪 Running Tests & Verification

Before submitting changes, ensure all tests pass:

```bash
# Run complete test suite
pytest -v

# Run a specific test module
pytest tests/test_static_scanner.py -v
pytest tests/test_desc_analyzer.py -v
pytest tests/test_dynamic_prober.py -v
pytest tests/test_pin_and_diff.py -v

# Run the 4-phase automated demonstration
python run_demo.py
```

---

## 📐 Code Style & Conventions

- Follow **PEP 8** style guidelines.
- Use explicit type annotations for function signatures (`typing.List`, `typing.Dict`, `typing.Optional`, etc.).
- Keep CLI output human-readable and colored via Rich formatting.
- Ensure all static and dynamic audit findings include:
  - Unique Rule ID (`MCP-XXX-NNN`)
  - Finding Title
  - Severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - Description and actionable remediation steps

---

## 📥 Submitting Pull Requests

1. **Create a branch**: `git checkout -b feature/your-feature-name` or `bugfix/issue-description`
2. **Make your changes** and add unit tests in `tests/` covering your changes.
3. **Verify the test suite**: Ensure `pytest` passes with 0 failures.
4. **Commit with clean commit messages**:
   ```bash
   git commit -m "feat(scanner): add detector for unescaped prompt templates"
   ```
5. **Open a Pull Request** against the `main` branch with a clear description of the problem solved.

---

## ⚖️ Contributor License Agreement

By contributing to this repository, you confirm that your contributions are your original work and you license them under the [MIT License](LICENSE).

---

## 📬 Questions & Community Contacts

Have questions or need guidance before opening a PR? Feel free to reach out to the project maintainers:
- **Saad Momin**: [Saadmomin940@gmail.com](mailto:Saadmomin940@gmail.com)
- **Sawez Farjad**: [sawezfarjad@gmail.com](mailto:sawezfarjad@gmail.com)
- **Security & Infrastructure**: [security@brextherfx.site](mailto:security@brextherfx.site)
