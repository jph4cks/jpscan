# jpscan — archived

**This project is archived and no longer maintained.**

### Use [rastro](https://github.com/jperezduerto/rastro) instead

`rastro` is jpscan's successor and does what this script's TODO list always
intended: a fast port sweep followed by automatic per-service enumeration.

The TODO block at the top of `jpscan.py` listed nikto and gobuster on HTTP,
EyeWitness, ike-scan, hydra default-credential checks, and SMTP user
enumeration. `rastro` implements that follow-on enumeration properly, driven by
a YAML rules file rather than hardcoded branches — so adding a service means
adding six lines of YAML, not editing Python.

What else changed:

- **Structured output.** A canonical `result.json`, a human-readable
  `report.md`, and every raw tool artifact preserved on disk. Every finding
  records the exact command that produced it.
- **Nothing silently dropped.** Anything `rastro` could not run — a missing
  tool, a service it wasn't confident enough about — is recorded with the
  command it would have run. A short findings list never quietly means "a tool
  wasn't installed".
- **Self-healing dependencies.** Missing tools are installed automatically.
- **Agent-ready.** Stable exit codes, a `--dry-run` that shows what would run
  without touching the target, and `rastro schema` for machine consumption.

```bash
git clone https://github.com/jperezduerto/rastro
cd rastro && pip install -e .
sudo rastro 10.0.0.5
```

`rastro` requires root and targets Linux.

---

This repository stays up for reference. The code here still runs, but it
receives no fixes or updates.

**Only scan systems you own or are explicitly authorized to test.**
