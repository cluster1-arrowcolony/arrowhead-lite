# META-SPEC.md: A Specification for the Specification

## Introduction

This document outlines the guiding principles for writing and maintaining a primary *specification* (`SPEC.md`). Its purpose is to establish a set of goals and constraints that ensure that the specification is clear, consistent, complete, and useful for its intended audiences. The `SPEC.md` is a living document, and this meta-specification serves as its constitution.

## Audiences

The `SPEC.md` must be written to serve multiple audiences, each with different needs. The design of the specification should always consider these audiences in order of priority:

1. **Implementers:** Those who implement the specification, including LLMs (Large Language Models) that parse, understand, and reason about the specification. They require absolute precision, formal definitions, and unambiguous rules.
2. **Users:** Individuals or other programs that interact with an implementation. They need clear explanations and an intuitive understanding of features to operate correctly and effectively.
3. **Architects:** Those guiding the evolution of the specification. They need to understand the rationale behind design decisions to ensure future changes are consistent and coherent.
4. **Tool Developers:** Those who build auxiliary tools or integrations. They need a blend of formal descriptions for parsing and semantic rules for analysis.

## Guiding Principles

The development and maintenance of `SPEC.md` shall adhere to the following principles.

### Clarity and Precision

The paramount goal of the specification is to be understood correctly and without ambiguity.

* **Unambiguity:** Every statement must have a single, clear interpretation. Where ambiguity is possible, the intended meaning must be explicitly stated. Formal definitions are the final authority. Do not use words such as "may", "might", "could", "should", "often", "typically", "usually", "generally", "some", "many", "few", "several", and similar terms that introduce uncertainty.
* **Conciseness:** Information should be presented as concisely as possible without sacrificing clarity or completeness.
* **Formalism:** Use formal notation where appropriate to define syntax, semantics, and behavior. Informal descriptions should complement, not replace, formal definitions.
* **Basic language**: Use clear and straightforward language. Avoid jargon and bureaucracy. Use boldface and italic sparingly, and do not use all caps for emphasis.

### Consistency and Cohesion

A consistent presentation reduces cognitive load and prevents errors in interpretation.

* **Terminology:** Use consistent terminology throughout the document. Define terms clearly upon first use and avoid synonyms for the same technical concept.
* **Structural Coherence:** All representations of a given concept, interface, or data structure must be mutually consistent, whether they appear in formal definitions, descriptive text, or illustrative examples.

### Completeness

The specification must be comprehensive and exhaustive.

* **Coverage:** The specification must describe all public features (API, CLI, environment variables, etc.) and behaviors that an implementation is required to support.
* **Explicitness:** Any behavior not explicitly defined in the specification is not part of the guaranteed behavior. The document should never leave behavior as "undefined".
* **Error Specification:** The nature of all expected error states must be specified, including the conditions under which they occur.

### Orthogonality and Managed Repetition

Information should be structured to prevent contradiction and duplication.

* **Single Source of Truth:** A core concept or rule should have a single, canonical definition. Other sections should reference this definition, not redefine it.
* **Managed Repetition for Clarity:** It is acceptable to present information at different levels of abstraction to guide the reader. However, all presentations must be consistent and free of contradiction.

### Rationale-Driven Design

The specification should document not just the "what", but also the "why".

* **Include Rationale:** Where a design decision is non-obvious or represents a significant trade-off, the specification should include a brief, non-normative note explaining the rationale.

### Textual Primacy

The specification's normative content must be conveyed through text, ensuring it is accessible, searchable, and unambiguous.

* **Authority of Text:** Diagrams, charts, and other non-textual elements may be used sparingly for illustrative purposes to aid understanding. However, they are always non-normative and inconsequential. The text is the final authority, and no requirement shall be conveyed through an image. The specification must be fully comprehensible on its own, by removing all non-textual elements.
* **Self-Explanation:** All illustrations must be accompanied by textual descriptions that fully explain the concept being illustrated. In case of any discrepancy between an illustration and the text, the text shall prevail.
* **Accessibility and Tooling:** A text-first approach ensures that the specification is accessible to screen readers and that its contents can be easily parsed, indexed, and validated by software tools.

### Self-Containment

The specification must be a standalone document.

* **No External References:** The specification must not reference external documents, websites, or resources that are not themselves immutable, versioned, and universally recognized standards. The behavior required for compliance cannot depend on a resource that might change or disappear.
* **Permissible References:** References to stable, globally recognized standards are permissible. When a reference is made, it must cite a specific, dated version of the external standard.

### Explicit Definitions

The specification must build its conceptual framework from a foundation of clear, unambiguous definitions.

* **Define Jargon:** Any technical term that is specific to this specification or is not part of a universally understood body of computer science knowledge must be explicitly defined. Definitions should be provided in a dedicated section or upon the first use of the term.
* **Glossary:** For specifications of sufficient complexity, a glossary of terms should be included to serve as a central reference.
* **Prerequisite Knowledge:** The specification may assume a baseline of knowledge from its audience (e.g., familiarity with TCP/IP, JSON), but this baseline should be minimal and, if necessary, stated explicitly in an introduction.

### Verifiability

A specification must be written in a way that is testable.

* **Concrete Assertions:** Every normative statement should be precise enough that a compliance test could, in principle, be written to verify it. Vague or subjective requirements should be avoided in normative sections in favor of falsifiable claims.
* **Decidability:** The rules defined in the specification should be such that for any given state or input, the expected behavior is unambiguously determined.

### Modularity

The structure of the specification should reflect the logical structure of the concepts it defines.

* **Logical Separation:** The specification should be organized into self-contained modules that correspond to distinct areas of functionality, allowing a reader to understand one area without needing to master all others.
* **Controlled Dependencies:** The description of a module should be as self-contained as possible, with any dependencies on other modules explicitly and clearly defined.

### Progressive Disclosure

The specification should be structured to be approachable and facilitate learning.

* **Layered Detail:** Information should be organized to allow a reader to build a mental model incrementally. High-level concepts and overviews should precede low-level formalisms and intricate details.
* **Conceptual Primacy:** The core concepts and design philosophy should be introduced first, providing a framework for understanding the specific rules and features that follow.

### Defined Scope and Boundaries

The specification must be as clear about what it *does not* define as what it *does*.

* **Implementation-Defined Behavior:** Explicitly identify areas where behavior is left to the discretion of an implementer.
* **Non-Guarantees:** Clearly state what is *not* guaranteed by the specification, such as internal architecture, performance characteristics, or the exact format of diagnostic messages.
* **Standard Delimitation:** Define where the standard defined by the specification ends and where a specific implementation's extensions or libraries begin.
