## Summary

Brief description of the changes in this PR.

## Related Issues

Closes #(issue number)

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Test improvements

## Changes Made

-
-
-

## Security Checklist

Memory Vault is security-critical software. Please verify:

- [ ] No sensitive data (keys, passwords, tokens) in code or logs
- [ ] Inputs are validated, especially from external sources
- [ ] Cryptographic operations follow existing patterns
- [ ] No new dependencies without security review
- [ ] Changes do not weaken the security model

## Testing

- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] New tests added for new functionality
- [ ] Manual testing performed

**Test commands run:**
```bash
pytest tests/ -v
ruff check .
```

## Documentation

- [ ] Code has appropriate docstrings and comments
- [ ] CHANGELOG.md updated (if user-facing changes)
- [ ] README.md updated (if new features)
- [ ] SPECIFICATION.md updated (if architectural changes)

## Checklist

- [ ] My code follows the project's code style
- [ ] I have performed a self-review of my code
- [ ] Pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)

## Additional Notes

Add any additional context or notes for reviewers.
