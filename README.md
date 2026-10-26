# CETRAINER Research

Technical research into CETRAINER protection and decoding.

## Case studies

- **Barracuda:** Watch Dogs trainer — analysis of the `BRICKED` signature and decoding procedure.
- **MrAntiFun:** Splinter Cell: Blacklist trainer — analysis of the `CHEAT` signature and verification of the decoded XML.

## Contents

- `CETRAINER_technical_notes_EN.md` OR `CETRAINER_technical_notes_RU.md` — detailed technical notes.
- `scripts/` — Python decoding and diagnostic scripts.

## Scope

The documented results apply to the specific samples analyzed. They do not imply universal compatibility with all CETRAINER files.

## Project Status and Scope

This repository documents an **amateur research project** focused on examining two specific protected Cheat Engine trainer samples: Barracuda's *Watch Dogs* trainer and MrAntiFun's *Splinter Cell: Blacklist* trainer.

The research explores their file structures, investigates existing unpacking approaches, and documents the methods that worked for the samples under examination. It is not intended to be a comprehensive, peer-reviewed study or a universal solution for decoding all `.CETRAINER` files.

### About the Scripts

The Python scripts in the `scripts/` directory are **working research utilities and temporary modifications developed during the investigation to obtain and examine the results documented here**.

They are included for transparency and reproducibility of the work, not presented as polished, production-ready software, a supported general-purpose toolkit, or a definitive implementation of the CETRAINER format.

Their behavior and compatibility may vary depending on the input file and environment. The scripts should be considered in the context of the specific research described in this repository.

### Scope of the Findings

The conclusions documented here apply to the particular samples examined during this investigation. They should not be assumed to apply to every trainer from the same authors or to every version of Cheat Engine.

The repository distinguishes observations confirmed for the examined samples from assumptions and behavior that has not been established for other files.

## Credits

The research references the original `cetrainer-unpacker` project by AlexAltea:
https://github.com/AlexAltea/cetrainer-unpacker
