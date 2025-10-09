#!/bin/bash
# generate-pdf-docs.sh - Compile all documentation into a single PDF

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
DOCS_DIR="$PROJECT_ROOT/docs"
OUTPUT_DIR="$PROJECT_ROOT/docs"
OUTPUT_FILE="arrowhead-lite-documentation.pdf"
TEMP_DIR=$(mktemp -d)

# Change to project root
cd "$PROJECT_ROOT"

# Check if pandoc is installed
check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"

    if ! command -v pandoc &> /dev/null; then
        echo -e "${RED}Error: pandoc is not installed${NC}"
        echo "Install with:"
        echo "  Ubuntu/Debian: sudo apt install pandoc texlive-latex-base texlive-fonts-recommended texlive-latex-extra"
        echo "  macOS: brew install pandoc basictex"
        echo "  Fedora: sudo dnf install pandoc texlive-scheme-basic"
        exit 1
    fi

    # Check for XeLaTeX (better Unicode support)
    if command -v xelatex &> /dev/null; then
        echo -e "${GREEN}✓ Using xelatex (best Unicode support)${NC}"
        PDF_ENGINE="xelatex"
    elif command -v pdflatex &> /dev/null; then
        echo -e "${YELLOW}! Using pdflatex (limited Unicode support)${NC}"
        PDF_ENGINE="pdflatex"
    else
        echo -e "${YELLOW}Warning: No LaTeX engine found. Using pandoc's built-in engine...${NC}"
        PDF_ENGINE=""
    fi

    echo -e "${GREEN}✓ Dependencies OK${NC}"
}

# Create metadata file
create_metadata() {
    cat > "$TEMP_DIR/metadata.yaml" << 'EOF'
---
title: "Arrowhead Lite Documentation"
subtitle: "Complete Guide and Reference"
author: "Arrowhead Lite Team"
date: \today
version: "1.0"
lang: en-US
papersize: a4
fontsize: 11pt
geometry: "margin=1in"
documentclass: report
toc: true
toc-depth: 3
numbersections: true
colorlinks: true
linkcolor: blue
urlcolor: blue
toccolor: black
header-includes: |
  \usepackage{fancyhdr}
  \pagestyle{fancy}
  \fancyhead[L]{Arrowhead Lite Documentation}
  \fancyhead[R]{\thepage}
  \fancyfoot[C]{}
  \usepackage{listings}
  \lstset{
    basicstyle=\ttfamily\footnotesize,
    breaklines=true,
    frame=single,
    backgroundcolor=\color{lightgray!10},
    keepspaces=true,
    columns=flexible
  }
  \usepackage{pmboxdraw}
---
EOF
}

# Combine all markdown files in order
combine_docs() {
    echo -e "${YELLOW}Combining documentation files...${NC}"

    # Document order - logical reading flow
    DOCS=(
        "README.md"                   # 1. Overview and introduction
        "ARCHITECTURE.md"             # 2. System design and components
        "APPLICATION_DEVELOPMENT.md"  # 3. Using Arrowhead Lite (applications)
        "COLONYOS_INTEGRATION.md"     # 4. Advanced: Compute orchestration integration
        "OPERATIONS_GUIDE.md"         # 5. Deploying and operating
        "API_REFERENCE.md"            # 6. Detailed API specification
        "DEVELOPMENT.md"              # 7. Contributing to the codebase
        "QUICK_REFERENCE.md"          # 8. Commands and config cheat sheet
    )

    # Diagrams to include
    DIAGRAMS=(
        "diagrams/README.md"
        "diagrams/1-cert-generation-dev.md"
        "diagrams/2-system-service-registration.md"
        "diagrams/3-orchestration-flow.md"
        "diagrams/4-service-consumption.md"
        "diagrams/5-authorization-rule-creation.md"
    )

    # Create combined markdown file
    COMBINED_FILE="$TEMP_DIR/combined.md"

    # Add title page content
    cat > "$COMBINED_FILE" << EOF
\\newpage

# About This Documentation

This documentation covers all aspects of Arrowhead Lite, a lightweight IoT service mesh implementing the Arrowhead Framework 4.x specification.

## Document Organization

This PDF is organized into the following sections:

1. **Overview** - Introduction and getting started
2. **Architecture** - System design and components (understand the system first)
3. **Application Development** - For application programmers using Arrowhead Lite
4. **ColonyOS Integration** - Advanced: Combining with compute orchestration
5. **Operations Guide** - For system administrators deploying Arrowhead Lite
6. **API Reference** - Complete REST API specification
7. **Development** - Contributing to the Arrowhead Lite codebase
8. **Quick Reference** - Command and configuration cheat sheet (handy reference)
9. **Visual Diagrams** - Sequence diagrams illustrating system interactions

## Version Information

- Documentation Version: 1.0
- Arrowhead Lite Version: 1.x
- Last Updated: $(date +%Y-%m-%d)

## Getting Help

- GitHub: https://github.com/cluster1-arrowcolony/arrowhead-lite
- Issues: https://github.com/cluster1-arrowcolony/arrowhead-lite/issues

\\newpage

EOF

    # Append each document
    for doc in "${DOCS[@]}"; do
        if [ -f "$DOCS_DIR/$doc" ]; then
            # Get file size for verification
            SIZE=$(wc -l < "$DOCS_DIR/$doc")
            echo -e "  Adding $doc ($SIZE lines)..."

            # Add page break before each major section
            echo "" >> "$COMBINED_FILE"
            echo '\newpage' >> "$COMBINED_FILE"
            echo "" >> "$COMBINED_FILE"

            # Add the document
            cat "$DOCS_DIR/$doc" >> "$COMBINED_FILE"
        else
            echo -e "${YELLOW}  Warning: $doc not found at $DOCS_DIR/$doc, skipping${NC}"
        fi
    done

    # Add diagrams section
    echo -e "${YELLOW}Adding visual diagrams...${NC}"
    echo "" >> "$COMBINED_FILE"
    echo '\newpage' >> "$COMBINED_FILE"
    echo "" >> "$COMBINED_FILE"
    echo "# Visual Diagrams" >> "$COMBINED_FILE"
    echo "" >> "$COMBINED_FILE"
    echo "This section contains sequence diagrams that illustrate key system interactions." >> "$COMBINED_FILE"
    echo "" >> "$COMBINED_FILE"

    # Append each diagram
    for diagram in "${DIAGRAMS[@]}"; do
        if [ -f "$DOCS_DIR/$diagram" ]; then
            SIZE=$(wc -l < "$DOCS_DIR/$diagram")
            echo -e "  Adding $diagram ($SIZE lines)..."

            # Add page break before each diagram
            echo "" >> "$COMBINED_FILE"
            echo '\newpage' >> "$COMBINED_FILE"
            echo "" >> "$COMBINED_FILE"

            # Add the diagram
            cat "$DOCS_DIR/$diagram" >> "$COMBINED_FILE"
        else
            echo -e "${YELLOW}  Warning: $diagram not found at $DOCS_DIR/$diagram, skipping${NC}"
        fi
    done

    # Show combined file statistics
    TOTAL_LINES=$(wc -l < "$COMBINED_FILE")
    TOTAL_SIZE=$(du -h "$COMBINED_FILE" | cut -f1)
    echo -e "${GREEN}✓ Documentation combined: $TOTAL_LINES lines, $TOTAL_SIZE${NC}"
}

# Generate PDF
generate_pdf() {
    echo -e "${YELLOW}Generating PDF...${NC}"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Pandoc options
    PANDOC_OPTS=(
        --from markdown+yaml_metadata_block+fenced_code_blocks
        --to pdf
        --metadata-file="$TEMP_DIR/metadata.yaml"
        --highlight-style=tango
        --standalone
        --verbose
        --listings
        -V block-headings
    )

    # Add PDF engine if available (prefer xelatex for better Unicode support)
    if [ -n "$PDF_ENGINE" ]; then
        PANDOC_OPTS+=(--pdf-engine="$PDF_ENGINE")
    fi

    echo -e "  Source file: $TEMP_DIR/combined.md"
    echo -e "  Output file: $OUTPUT_DIR/$OUTPUT_FILE"
    echo -e "  Running pandoc..."

    # Generate PDF
    if pandoc "${PANDOC_OPTS[@]}" \
        "$TEMP_DIR/combined.md" \
        -o "$OUTPUT_DIR/$OUTPUT_FILE" 2>&1 | tee "$TEMP_DIR/pandoc.log"; then

        if [ -f "$OUTPUT_DIR/$OUTPUT_FILE" ]; then
            PDF_SIZE=$(du -h "$OUTPUT_DIR/$OUTPUT_FILE" | cut -f1)
            PDF_PAGES=$(pdfinfo "$OUTPUT_DIR/$OUTPUT_FILE" 2>/dev/null | grep Pages | awk '{print $2}' || echo "unknown")
            echo -e "${GREEN}✓ PDF generated successfully${NC}"
            echo -e "  Size: $PDF_SIZE"
            echo -e "  Pages: $PDF_PAGES"
        else
            echo -e "${RED}Error: PDF file was not created${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Error generating PDF. Pandoc output:${NC}"
        cat "$TEMP_DIR/pandoc.log"
        echo ""
        echo -e "${RED}Combined markdown file available at: $TEMP_DIR/combined.md${NC}"
        exit 1
    fi
}

# Generate HTML version as well
generate_html() {
    echo -e "${YELLOW}Generating HTML version...${NC}"

    HTML_FILE="arrowhead-lite-documentation.html"

    pandoc \
        --from markdown \
        --to html5 \
        --standalone \
        --toc \
        --toc-depth=3 \
        --metadata title="Arrowhead Lite Documentation" \
        --highlight-style=tango \
        --css=https://cdn.jsdelivr.net/npm/github-markdown-css@5/github-markdown.min.css \
        --metadata-file="$TEMP_DIR/metadata.yaml" \
        "$TEMP_DIR/combined.md" \
        -o "$OUTPUT_DIR/$HTML_FILE"

    echo -e "${GREEN}✓ HTML generated successfully${NC}"
}

# Generate EPUB version
generate_epub() {
    echo -e "${YELLOW}Generating EPUB version...${NC}"

    EPUB_FILE="arrowhead-lite-documentation.epub"

    pandoc \
        --from markdown \
        --to epub3 \
        --toc \
        --toc-depth=3 \
        --metadata-file="$TEMP_DIR/metadata.yaml" \
        --highlight-style=tango \
        "$TEMP_DIR/combined.md" \
        -o "$OUTPUT_DIR/$EPUB_FILE"

    echo -e "${GREEN}✓ EPUB generated successfully${NC}"
}

# Cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main execution
main() {
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}Arrowhead Lite Documentation Generator${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""

    # Parse arguments
    GENERATE_HTML=false
    GENERATE_EPUB=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --html)
                GENERATE_HTML=true
                shift
                ;;
            --epub)
                GENERATE_EPUB=true
                shift
                ;;
            --all)
                GENERATE_HTML=true
                GENERATE_EPUB=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --html    Generate HTML version"
                echo "  --epub    Generate EPUB version"
                echo "  --all     Generate all formats (PDF, HTML, EPUB)"
                echo "  --help    Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                  # Generate PDF only"
                echo "  $0 --html           # Generate PDF and HTML"
                echo "  $0 --all            # Generate all formats"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Run generation steps
    check_dependencies
    create_metadata
    combine_docs
    generate_pdf

    if [ "$GENERATE_HTML" = true ]; then
        generate_html
    fi

    if [ "$GENERATE_EPUB" = true ]; then
        generate_epub
    fi

    cleanup

    # Print summary
    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}Documentation generation complete!${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""
    echo "Output location: $OUTPUT_DIR"
    echo ""
    echo "Generated files:"

    if [ -f "$OUTPUT_DIR/$OUTPUT_FILE" ]; then
        ls -lh "$OUTPUT_DIR/$OUTPUT_FILE"
    fi

    if [ "$GENERATE_HTML" = true ] && [ -f "$OUTPUT_DIR/arrowhead-lite-documentation.html" ]; then
        ls -lh "$OUTPUT_DIR/arrowhead-lite-documentation.html"
    fi

    if [ "$GENERATE_EPUB" = true ] && [ -f "$OUTPUT_DIR/arrowhead-lite-documentation.epub" ]; then
        ls -lh "$OUTPUT_DIR/arrowhead-lite-documentation.epub"
    fi

    echo ""
    echo "To view the PDF:"
    echo "  xdg-open $OUTPUT_DIR/$OUTPUT_FILE    # Linux"
    echo "  open $OUTPUT_DIR/$OUTPUT_FILE        # macOS"
    echo ""
    echo -e "${GREEN}✓ All done!${NC}"
}

# Run main function
main "$@"
