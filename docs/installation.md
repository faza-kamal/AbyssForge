# Installation Guide

## Requirements

- Python 3.9 or higher
- pip package manager
- Git

## Method 1: Clone from GitHub (Recommended)

```bash
git clone https://github.com/faza-kamal/AbyssForge.git
cd AbyssForge
pip install -e .
```

## Method 2: pip install

```bash
pip install git+https://github.com/faza-kamal/AbyssForge.git
```

## Method 3: Docker

```bash
docker pull ghcr.io/faza-kamal/abyssforge:latest
docker run --rm abyssforge --help
```

Or build locally:
```bash
git clone https://github.com/faza-kamal/AbyssForge.git
cd AbyssForge
docker build -t abyssforge .
docker run --rm abyssforge --help
```

## Verify Installation

```bash
abyssforge --version
abyssforge modules
```

## Troubleshooting

**SSL errors**: Use `--no-verify-ssl` flag
**Rate limiting**: Reduce `--rate-limit` value
**Timeout errors**: Increase `--timeout` value

## Updating

```bash
cd AbyssForge
git pull origin main
pip install -e .
```
