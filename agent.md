# Agent operations guide

The canonical repository instructions are in [AGENTS.md](AGENTS.md).
The VM startup, restart, logging, configuration, deployment, testing, backup and
restore commands are in [README.md](README.md).

Production runs on `dhanush.kumar@connect` in `/home/dhanush.kumar/phishing`.
Keep the laptop worker stopped while the VM is active. Use the existing Compose
project `phishing-analyzer` and preserve its private `.env` and evidence volume.

Maintain instructions in `AGENTS.md` and commands in `README.md`; this filename is
a pointer for users/tools that look for `agent.md`, not a separate policy copy.
