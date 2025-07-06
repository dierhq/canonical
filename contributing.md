# Contributing to Canonical SIEM Rule Converter

Thank you for your interest in contributing to Canonical! We welcome contributions from the cybersecurity community to help improve this tool for SOCs, MDRs, and security teams worldwide.

## 🎯 Contribution Guidelines

### 🏢 License Compliance
Before contributing, please note that this project is licensed under a **Custom License** that restricts commercial use. By contributing, you agree that:
- Your contributions will be subject to the same license terms
- Contributions are for the benefit of the cybersecurity community
- You will not use contributions to create competing commercial products

## 🤝 How to Contribute

### 🐛 Bug Reports
Help us improve by reporting bugs:

1. **Search existing issues** to avoid duplicates
2. **Use the bug report template**
3. **Provide detailed information**:
   - Operating system and Python version
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Error messages and logs
   - Sample rules (if applicable)

### 💡 Feature Requests
Suggest new features or improvements:

1. **Check GitHub Discussions** for existing requests
2. **Create a detailed proposal** including:
   - Use case and business justification
   - Proposed implementation approach
   - Impact on existing functionality
   - Target user groups (SOCs, MDRs, etc.)

### 🔧 Code Contributions

#### Prerequisites
- Python 3.9+
- Git knowledge
- Understanding of SIEM concepts
- Familiarity with the project architecture

#### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/canonical.git
cd canonical

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip3 install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run initial data ingestion
python3 -m src.canonical.cli data ingest-all --force-refresh
```

#### Development Workflow
1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run quality checks**
   ```bash
   # Format code
   black src/ tests/
   
   # Sort imports
   isort src/ tests/
   
   # Type checking
   mypy src/
   
   # Linting
   flake8 src/ tests/
   
   # Run tests
   pytest tests/
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add support for new SIEM format"
   ```

5. **Push and create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

#### Pull Request Guidelines
- **Clear title and description**
- **Reference related issues**
- **Include tests** for new functionality
- **Update documentation** if needed
- **Ensure all checks pass**
- **Keep changes focused** (one feature per PR)

## 📋 Development Standards

### Code Style
- **PEP 8** compliance
- **Type hints** for all functions
- **Docstrings** for classes and functions
- **Meaningful variable names**
- **Error handling** with appropriate logging

### Testing
- **Unit tests** for core functionality
- **Integration tests** for API endpoints
- **Test coverage** should not decrease
- **Test data** should be representative

### Documentation
- **Code comments** for complex logic
- **API documentation** for new endpoints
- **README updates** for new features
- **Examples** for new functionality

## 🏗️ Architecture Guidelines

### Adding New SIEM Formats
1. **Create parser** in `src/canonical/parsers/`
2. **Add conversion logic** in `src/canonical/core/converter.py`
3. **Update models** in `src/canonical/core/models.py`
4. **Add tests** in `tests/`
5. **Update documentation**

### Adding New Data Sources
1. **Create ingestion script** in `src/canonical/data_ingestion/`
2. **Update configuration** in `src/canonical/core/config.py`
3. **Add CLI commands** in `src/canonical/cli.py`
4. **Add collection setup** in `src/canonical/services/chromadb.py`

### Performance Considerations
- **Memory efficiency** for large datasets
- **Async/await** for I/O operations
- **Batch processing** for bulk operations
- **Caching** for frequently accessed data

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/canonical

# Run specific test file
pytest tests/test_converter.py

# Run with verbose output
pytest -v
```

### Test Categories
- **Unit Tests**: Test individual components
- **Integration Tests**: Test component interactions
- **API Tests**: Test REST endpoints
- **End-to-End Tests**: Test complete workflows

## 📖 Documentation

### Types of Documentation
- **Code Documentation**: Docstrings and comments
- **API Documentation**: OpenAPI/Swagger specs
- **User Documentation**: Installation and usage guides
- **Developer Documentation**: Architecture and contributing guides

### Documentation Standards
- **Clear and concise** language
- **Step-by-step** instructions
- **Code examples** where applicable
- **Screenshots** for UI components

## 🔍 Review Process

### Code Review Criteria
- **Functionality**: Does it work as intended?
- **Security**: Are there any security implications?
- **Performance**: Does it impact system performance?
- **Maintainability**: Is the code easy to understand and modify?
- **Testing**: Are there adequate tests?

### Review Timeline
- **Initial response**: Within 48 hours
- **Full review**: Within 1 week
- **Follow-up**: As needed for clarifications

## 🚀 Release Process

### Version Numbering
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped
- [ ] Tagged release created

## 🤔 Questions and Support

### Getting Help
- **GitHub Discussions**: For questions and feature discussions
- **GitHub Issues**: For bug reports and technical issues
- **Email**: team@dierhq.com for sensitive issues

### Community Guidelines
- **Be respectful** and professional
- **Stay on topic** and relevant to the project
- **Help others** when you can
- **Follow the code of conduct**

## 🎖️ Recognition

### Contributor Recognition
- **Contributors list** in README.md
- **Release notes** mention significant contributions
- **Special recognition** for major features or fixes

### Types of Contributions
- **Code contributions**: New features, bug fixes, optimizations
- **Documentation**: Guides, examples, API docs
- **Testing**: Test cases, quality assurance
- **Community**: Answering questions, code reviews
- **Security**: Vulnerability reports, security improvements

## 📋 Checklist for Contributors

Before submitting your contribution:

- [ ] I have read and understood the license terms
- [ ] My code follows the project's coding standards
- [ ] I have added tests for my changes
- [ ] All existing tests still pass
- [ ] I have updated documentation as needed
- [ ] My commits have clear, descriptive messages
- [ ] I have tested my changes thoroughly
- [ ] My changes do not introduce security vulnerabilities

## 🙏 Thank You

Thank you for contributing to Canonical! Your efforts help make cybersecurity tools more accessible and effective for the entire community. Together, we're building better security for everyone.

---

**Questions?** Feel free to reach out to us at team@dierhq.com or start a discussion on GitHub.

**DIER Team** 🛡️ 