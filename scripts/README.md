# Arrowhead Lite Scripts

## PDF Documentation Generation

### generate-pdf-docs.sh

Generates a comprehensive PDF from all documentation files.

**Features:**
- Combines all documentation into a single PDF with table of contents
- Supports HTML and EPUB output formats
- Proper Unicode handling for ASCII diagrams
- Box-drawing character rendering
- Syntax highlighting for code blocks

**Requirements:**

For best results, install XeLaTeX (better Unicode support):

```bash
# Ubuntu/Debian
sudo apt-get install pandoc texlive-xetex texlive-fonts-recommended fonts-dejavu

# macOS
brew install pandoc
brew install --cask basictex
sudo tlmgr install xetex dejavu

# Fedora
sudo dnf install pandoc texlive-scheme-basic texlive-xetex dejavu-sans-fonts dejavu-serif-fonts dejavu-sans-mono-fonts
```

**Usage:**

```bash
# Generate PDF only
./scripts/generate-pdf-docs.sh

# Generate PDF and HTML
./scripts/generate-pdf-docs.sh --html

# Generate all formats (PDF, HTML, EPUB)
./scripts/generate-pdf-docs.sh --all
```

**Output:**
- PDF: `docs/arrowhead-lite-documentation.pdf`
- HTML: `docs/arrowhead-lite-documentation.html` (if requested)
- EPUB: `docs/arrowhead-lite-documentation.epub` (if requested)

### Diagram Rendering

The script handles ASCII diagrams and box-drawing characters using the `pmboxdraw` LaTeX package:

**XeLaTeX (recommended):**
- Best Unicode support for box-drawing characters
- Better overall font rendering
- Handles complex diagrams properly

**pdflatex (fallback):**
- Basic Unicode support via `pmboxdraw` package
- May have limited rendering for complex diagrams

The script automatically detects and uses XeLaTeX if available, falling back to pdflatex otherwise.

## Certificate Generation

### generate-certs.sh

Generates development certificates for Arrowhead Lite. See [../docs/diagrams/1-cert-generation-dev.md](../docs/diagrams/1-cert-generation-dev.md) for details.

**Warning:** Only for development. Do not use in production.

```bash
./scripts/generate-certs.sh
```
