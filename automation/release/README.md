# NSS Release Documentation and Email Generation Scripts

This directory contains Python scripts to automate the generation of NSS release documentation and release announcement emails.

## Scripts

### 1. `generate_release_doc.py`

Generates the RST documentation file for an NSS release based on the version number and commit history.

**Usage:**
```bash
python3 generate_release_doc.py <version> <previous_version> [output_file]
```

**Arguments:**
- `<version>`: The version being released (e.g., `3.118` or `3.118.1`)
- `<previous_version>`: The previous release version (e.g., `3.117`)
- `[output_file]`: Optional. Path where to write the RST file. If not provided, defaults to `doc/rst/releases/nss_<version>.rst`

**Examples:**
```bash
# Generate documentation for NSS 3.118
python3 automation/release/generate_release_doc.py 3.118 3.117

# Generate documentation for NSS 3.118.1 with custom output path
python3 automation/release/generate_release_doc.py 3.118.1 3.118 doc/rst/releases/nss_3_118_1.rst
```

**What it does:**
1. Reads the required NSPR version from `automation/release/nspr-version.txt`
2. Extracts bug changes from Mercurial log between the two version tags
3. Generates an RST file following the standard NSS release notes format
4. Includes release date, distribution information, and all bug fixes

### 2. `generate_release_email.py`

Generates the release announcement email text based on the version number and commit history.

**Usage:**
```bash
python3 generate_release_email.py <version> <previous_version> [output_file]
```

**Arguments:**
- `<version>`: The version being released (e.g., `3.118` or `3.118.1`)
- `<previous_version>`: The previous release version (e.g., `3.117`)
- `[output_file]`: Optional. Path where to write the email text. If not provided, prints to stdout

**Examples:**
```bash
# Generate email for NSS 3.118 (print to stdout)
python3 automation/release/generate_release_email.py 3.118 3.117

# Generate email for NSS 3.118.1 and save to file
python3 automation/release/generate_release_email.py 3.118.1 3.118 release_email_3.118.1.txt
```

**What it does:**
1. Reads the required NSPR version from `automation/release/nspr-version.txt`
2. Extracts bug changes from Mercurial log between the two version tags
3. Generates email text following the standard NSS release announcement format
4. Includes release date, distribution information, all bug fixes, and compatibility notes

## Requirements

Both scripts require:
- Python 3
- Mercurial (`hg` command)
- Must be run from the NSS repository root directory
- Release tags must exist in the repository (e.g., `NSS_3_118_RTM`, `NSS_3_117_RTM`)

## Complete Release Workflow

For a complete NSS release (e.g., NSS 3.118), follow these steps:

1. **Generate the release documentation:**
   ```bash
   cd /path/to/nss
   python3 automation/release/generate_release_doc.py 3.118 3.117
   ```

2. **Update the release notes index** (if needed):
   - Edit `doc/rst/releases/index.rst` to add the new release at the top of the toctree
   - Update the "latest version" note

3. **Generate the release email:**
   ```bash
   python3 automation/release/generate_release_email.py 3.118 3.117 > release_email.txt
   ```

4. **Review and commit:**
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

- The scripts automatically extract the current date for the release date
- Bug entries are automatically formatted and deduplicated
- The scripts read the NSPR version from `automation/release/nspr-version.txt`
- Only commits with "Bug XXXXXX" in the message are included in the changes list

