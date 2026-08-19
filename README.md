# ML License Compliance Agent

> Submitted to the [GitLab AI Hackathon](https://gitlab.devpost.com/) | [Live Demo](https://ml-license-agent.netlify.app) | [Devpost](https://devpost.com/software/aryaay-tech)

Automated ML license compliance — catches GPL, Llama, and CC-BY-NC violations before they ship.

## What It Does

The ML License Compliance Agent scans your ML project for license violations across three areas:

- **Python packages** — detects dangerous licenses hiding in your dependencies
- **Hugging Face models** — flags misuse of models with strict licenses (e.g. Llama's restrictions on using outputs to train other models)
- **Training datasets** — identifies datasets that can't legally be used in commercial products (e.g. CC-BY-NC)

Trigger it by commenting on any GitLab issue or MR — it replies with a full compliance report including specific violations, exact license clauses, and steps to fix each one. It also runs automatically in CI/CD and blocks merges when critical violations are found.

## Demo

[![Demo Video](https://img.shields.io/badge/Watch%20Demo-Vimeo-blue)](https://vimeo.com/1176847264)

![Demo Screenshot](https://d112y698adiu2z.cloudfront.net/photos/production/software_photos/004/493/054/datas/gallery.jpg)

## How It Works

- The scanner is Python code that reads your repo files and calls public APIs (deps.dev, Hugging Face) to look up license information
- Claude powers the interactive layer via the **GitLab Duo Agent Platform** — when a developer doesn't understand a finding, they ask the agent and get a plain-English explanation with fix steps
- CycloneDX handles dependency bill-of-materials generation

## Built With

- Python
- Claude API (GitLab Duo Agent Platform)
- GitLab CI/CD
- Hugging Face API
- deps.dev
- CycloneDX
- Netlify (demo site)

## Team

Built by [Ayaan Ali](https://devpost.com/ayaana2), [Archit Jaiswal](https://devpost.com/archit4), and [Yatharth Sharma](https://devpost.com/yath-shar-2007).
