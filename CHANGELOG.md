# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-05-15

### Added
- Enterprise-grade `Finding` model with rich contextual fields (`business_impact`, `remediation_steps`, `cvss_score`, etc.).
- Complete transition from the legacy Tkinter GUI to a modular, professional CLI architecture.
- Modular architecture with clean separation of `core/`, `checks/`, `platforms/`, and `reports/`.
- Advanced HTML and PDF report generation matching commercial enterprise tools.
- Strict Type Hints and Docstrings across all core components and checks.
- New behavioral detection approach in `running_processes_check.py` instead of naive binary matching.
- Multi-platform support (Linux, macOS, Windows) orchestrated via a clean Factory pattern.

### Changed
- Refactored all 8 legacy checks into class-based plugins inheriting from `BaseCheck`.
- Improved scoring algorithm to use logarithmic/diminishing penalties instead of linear deduction.
- Refined check severities to accurately reflect actual risk (e.g. empty passwords = CVSS 9.8).
- Updated open port analysis to accurately distinguish between localhost bindings and external exposure.

### Removed
- Legacy Tkinter GUI components.
- Hardcoded legacy wrappers (e.g. `check_suspicious_processes()`) from check modules.
