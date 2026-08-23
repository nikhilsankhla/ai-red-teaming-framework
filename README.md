# AI Red Teaming Framework

An interactive tool for exploring how LLM prompt-injection attacks are detected. Paste text
into the injection tester and it scores the input against a set of adversarial pattern
classes, showing which techniques it matches and why — plus a simulated adversarial
test-suite walkthrough.

> **Sanitised / educational.** The detection patterns are generalised signatures, not client
> data, and nothing here is under NDA. No AI model is called — see below.

**Live demo:** [nikhilsec.com/projects/ai-red-teaming](https://nikhilsec.com/projects/ai-red-teaming)
— or open `index.html` locally, or host it on GitHub Pages.

## What it is

A sanitised, NDA-compliant adversarial-testing toolkit distilled from active red-teaming
campaigns against frontier LLMs. It packages a jailbreak taxonomy, a prompt-injection
detection pipeline, and a simulated multi-category adversarial test suite into a single
static page — a portable reference for how LLM red-teaming is structured, without exposing
any client engagement details.

## What it demonstrates

- **Prompt Injection Tester** — scans input against pattern classes for known injection
  techniques (system-prompt override, indirect injection via data, role-play jailbreaks,
  encoding/obfuscation, data exfiltration prompts, and more), and returns a weighted risk
  score with the matched vectors explained.
- **LLM Jailbreak Taxonomy** — 8 attack categories and 40+ techniques with success-rate
  tracking, giving a structured vocabulary for what a jailbreak attempt actually is.
- **Adversarial Test Suite** — a simulated run of 200+ categorised adversarial prompts across
  safety, alignment, and robustness, illustrating how a red-team harness reports pass/fail
  per technique.
- **Multimodal attack-surface mapping** — text, image, audio, and tool-use vectors laid out
  as a reference for where injection risk shows up beyond plain text prompts.

## How it works

The injection tester is **pure regex heuristics — no AI model is called.** Each pattern class
maps to a documented adversarial technique and carries a severity weight; the risk score is
the weighted aggregate of what matched. This is deliberate: it's a fast, transparent,
offline detector you can read and reason about, not a black box. The patterns are
generalised from public injection research and sanitised engagement notes.

## Requirements / tools

None — pure client-side JavaScript/HTML/CSS. Any modern browser, or a static file server for
local testing.

## Setup / usage

```bash
git clone https://github.com/nikhilsankhla/ai-red-teaming-framework.git
cd ai-red-teaming-framework
python3 -m http.server 8000    # then open http://localhost:8000
```

Or just open `index.html` directly.

## Project structure

```
index.html              the tool — injection tester, taxonomy, test-suite views
css/
  main.css               shared portfolio-site styling
  ai_red_teaming.css      page-specific styling
js/
  ai_red_teaming.js       pattern classes, scoring logic, simulated test suite
LICENSE
```

## Skills demonstrated

- LLM security / adversarial ML: jailbreak taxonomy design, prompt-injection pattern
  research, and turning red-team findings into a reusable detection signature set
- Applying a weighted-scoring model to heterogeneous attack signals (severity per matched
  pattern class, aggregated into one risk score)
- Sanitising real engagement work for public release without leaking client-specific or
  NDA-covered detail
- Front-end engineering with zero dependencies and no build step — readable, auditable
  client-side code by design

## Defensive / security takeaways

Educational and defensive. It demonstrates how injection *detection* works and how a
red-team harness is structured; it is not a jailbreak toolkit and ships no working exploits.
The core lesson: regex/pattern-based detection is fast and transparent but is a first line of
defense, not a complete one — it catches known technique *signatures*, not novel phrasing of
the same underlying attack, which is why production defenses layer this with model-based
classifiers and output-side controls.

## Built with

`JavaScript` · `HTML` · `CSS` — client-side, no build step, no dependencies.

## Project page

[nikhilsec.com/projects/ai-red-teaming](https://nikhilsec.com/projects/ai-red-teaming)

## License

MIT — see [LICENSE](LICENSE).

---
<sub>Part of my security portfolio — more at <a href="https://nikhilsec.com">nikhilsec.com</a></sub>
