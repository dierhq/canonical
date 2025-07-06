---
name: Bug Report
about: Create a report to help us improve Canonical
title: '[BUG] Brief description of the issue'
labels: bug
assignees: ''
---

## 🐛 Bug Description
A clear and concise description of what the bug is.

## 🔄 Steps to Reproduce
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## ✅ Expected Behavior
A clear and concise description of what you expected to happen.

## ❌ Actual Behavior
A clear and concise description of what actually happened.

## 📋 Environment Information
- **OS**: [e.g. Ubuntu 20.04, macOS 12.0, Windows 11]
- **Python Version**: [e.g. 3.9.7]
- **Canonical Version**: [e.g. 0.1.0]
- **Installation Method**: [e.g. pip, source, docker]

## 📄 Sample Rule (if applicable)
```yaml
# Paste your Sigma rule or other relevant rule here
title: Example Rule
detection:
  condition: selection
  selection:
    EventID: 4688
```

## 📊 Conversion Details (if applicable)
- **Source Format**: [e.g. Sigma]
- **Target Format**: [e.g. KustoQL]
- **Error Message**: 
```
Paste any error messages here
```

## 📸 Screenshots
If applicable, add screenshots to help explain your problem.

## 🔍 Additional Context
Add any other context about the problem here.

## 🛠️ Possible Solution
If you have ideas about what might be causing the issue or how to fix it, please share them here.

## ✅ Checklist
- [ ] I have searched existing issues to ensure this is not a duplicate
- [ ] I have provided all the requested information
- [ ] I have tested this with the latest version
- [ ] I understand this is for internal use within SOCs/MDRs/corporate security teams 