# Contributing to Arrowhead Lite

Thank you for your interest in contributing to Arrowhead Lite! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

- **Search existing issues** first to avoid duplicates
- Use the issue template and provide:
  - Clear description of the problem
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment details (OS, Go version, etc.)

### Suggesting Features

- Open an issue with the `enhancement` label
- Describe the use case and benefit
- Discuss the approach before implementing large features

### Submitting Pull Requests

1. **Fork and clone** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Make your changes**:
   - Write clear, documented code
   - Add tests for new functionality
   - Update documentation as needed
4. **Run tests**: `make check` (runs formatting, linting, and tests)
5. **Commit with conventional commits**:
   ```
   feat: add temperature sensor support

   - Implements new temperature service interface
   - Adds unit tests
   - Updates API documentation

   Closes #123
   ```
6. **Push and create PR** to the `main` branch
7. **Respond to review feedback**

## Development Setup

See [docs/DEVELOPMENT.md](./docs/DEVELOPMENT.md) for complete development environment setup, including:
- Prerequisites and tooling
- Building and testing
- Code style and conventions
- Debugging tips

## Commit Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only changes
- `style:` - Code style changes (formatting, no logic change)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Build process, dependencies, or tooling changes

## Code Review

Pull requests are reviewed for:
- Tests pass and coverage is maintained
- Code follows project conventions
- Documentation is updated
- No security vulnerabilities introduced
- Performance impact is considered
- Backward compatibility is maintained

## Code of Conduct

- Be respectful and constructive
- Focus on the technical merits of contributions
- Help maintain a welcoming community

## Questions?

- Check the [documentation](./docs/)
- Ask in GitHub Discussions or open an issue with the `question` label

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](./LICENSE)).
