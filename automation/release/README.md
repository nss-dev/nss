# NSS Release Documentation and Email Generation Scripts

This directory contains Python scripts to automate the generation of NSS release documentation and release announcement emails.

## Scripts

### 1. `generate_release_doc.py`

Generates the RST documentation file for an NSS release based on the version number and commit history.

**Usage:**
```bash
python3 generate_release_doc.py <version> [output_file]
```

**Arguments:**
- `<version>`: The version being released (e.g., `3.118` or `3.118.1`)
- `[output_file]`: Optional. Path where to write the Markdown file. If not provided, defaults to `doc/src/releases/nss_<version>.md`

**Examples:**
```bash
# Generate documentation for NSS 3.118
python3 automation/release/generate_release_doc.py 3.118

# Generate documentation for NSS 3.118.1 with custom output path
python3 automation/release/generate_release_doc.py 3.118.1 doc/src/releases/nss_3_118_1.md
```

**What it does:**
1. Reads the required NSPR version from `automation/release/nspr-version.txt` at the RTM tag revision (or current file if the tag does not yet exist)
2. Extracts bug changes from Mercurial log for the given version
3. Generates an RST file following the standard NSS release notes format
4. Includes release date, distribution information, and all bug fixes

### 2. `generate_release_email.py`

Generates the release announcement email text based on the version number and commit history.

**Usage:**
```bash
python3 generate_release_email.py <version> [output_file]
```

**Arguments:**
- `<version>`: The version being released (e.g., `3.118` or `3.118.1`)
- `[output_file]`: Optional. Path where to write the email text. If not provided, prints to stdout

**Examples:**
```bash
# Generate email for NSS 3.118 (print to stdout)
python3 automation/release/generate_release_email.py 3.118

# Generate email for NSS 3.118.1 and save to file
python3 automation/release/generate_release_email.py 3.118.1 release_email_3.118.1.txt
```

**What it does:**
1. Reads the required NSPR version from `automation/release/nspr-version.txt` at the RTM tag revision (or current file if the tag does not yet exist)
2. Extracts bug changes from Mercurial log for the given version
3. Generates email text following the standard NSS release announcement format
4. Includes release date, distribution information, all bug fixes, and compatibility notes

## Requirements

Both scripts require:
- Python 3
- Mercurial (`hg` command)
- Must be run from the NSS repository root directory

## Complete Release Workflow

For a complete NSS release (e.g., NSS 3.118), follow these steps:

1. **Generate the release documentation:**
   ```bash
   cd /path/to/nss
   python3 automation/release/generate_release_doc.py 3.118
   ```

2. **Update the release notes index:**
   ```bash
   python3 automation/release/nss-release-helper.py generate_release_notes_index 3.118 3.112.1
   ```
   This rewrites the toctree in `doc/src/releases/index.md` and the "latest
   version" note. A new release note that is not in the toctree makes
   `doc-lint` fail, so this has to happen before the next step.

   Passing a single version updates only the latest-release note and keeps the
   ESR version already recorded in the index:
   ```bash
   python3 automation/release/nss-release-helper.py generate_release_notes_index 3.118
   ```

3. **Check the documentation builds cleanly:**
   ```bash
   ./mach doc-lint
   ```

4. **Generate the release email:**
   ```bash
   python3 automation/release/generate_release_email.py 3.118 release_email.txt
   ```

5. **Review and commit:**
   - Review the generated documentation
   - Commit the new release notes to the repository
   - Send the release email to the appropriate mailing list

## Integration with Existing Tools

These scripts complement the existing `nss-release-helper.py` script, which provides a complete automated release workflow. You can use these standalone scripts if you need to:
- Regenerate documentation after tags have been created
- Generate release notes for hotfix releases
- Create documentation for past releases
- Test documentation generation before running the full release process

## Notes

- The release date and NSPR version are taken from the RTM tag when it exists, and fall back to today's date and the current `nspr-version.txt` otherwise
- Bug entries are automatically formatted and deduplicated
- Only commits with "Bug XXXXXX" in the message are included in the changes list
