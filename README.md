# AI Red Teaming Framework

An interactive tool for exploring how LLM prompt-injection attacks are detected. Paste text
into the injection tester and it scores the input against a set of adversarial pattern
classes, showing which techniques it matches and why — plus a simulated adversarial
test-suite walkthrough.

> **Sanitised / educational.** The detection patterns are generalised signatures, not client
> data, and nothing here is under NDA. No AI model is called — see below.

**Live demo:** open `index.html` in a browser, or host it on GitHub Pages.

## What it does

- **Prompt Injection Tester** — scans input against pattern classes for known injection
  techniques (system-prompt override, indirect injection via data, role-play jailbreaks,
  encoding/obfuscation, data exfiltration prompts, and more), and returns a weighted risk
  score with the matched vectors explained.
- **Adversarial Test Suite** — a simulated run of categorised adversarial prompts against a
  target, illustrating how a red-team harness reports pass/fail per technique.

## How it works

The injection tester is **pure regex heuristics — no AI model is called.** Each pattern class
maps to a documented adversarial technique and carries a severity weight; the risk score is
the weighted aggregate of what matched. This is deliberate: it's a fast, transparent,
offline detector you can read and reason about, not a black box. The patterns are
generalised from public injection research and sanitised engagement notes.

## Run it

```bash
git clone https://github.com/nikhilsankhla/ai-red-teaming-framework.git
cd ai-red-teaming-framework
python3 -m http.server 8000    # then open http://localhost:8000
```

Or just open `index.html`.

## Built with

`JavaScript` · `HTML` · `CSS` — client-side, no build step, no dependencies.

## Scope

Educational and defensive. It demonstrates how injection *detection* works and how a
red-team harness is structured; it is not a jailbreak toolkit and ships no working exploits.

## License

MIT — see [LICENSE](LICENSE).

---
<sub>Part of my security portfolio — more at <a href="https://nikhilsec.com">nikhilsec.com</a></sub>
