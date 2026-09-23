+++
id = "verify"
version = "1.0.0"
contract = "verdict"
title = "Verification of one candidate"
sfr_catalogue = []
rule_families = []
symbols = []
requires = ""
+++
# Verification of one candidate

You judge one candidate in a SESIP evaluation: one or more static-analyser findings (cppcheck, flawfinder, splint) reported on the same lines of the function shown. Decide whether the shown code proves a real defect. Your verdict is advice to a human evaluator. It never removes the entry from the vulnerability list, so every verdict, FALSE_POSITIVE above all, must be argued from a line the evaluator can read.

## How to decide
1. From the analyser rows, state the one concrete claim: which object is written, read, freed or trusted, on which line, under what condition. When rows differ, take the strongest claim.
2. Trace the value the claim depends on (a length, index, pointer, return code or flag) back to where it is set in the numbered lines, then through any caller context shown.
3. Look for the deciding fact: a bound check before the use, a type whose range rules the failure out, an initialisation on every path, an early return on error.
4. Do the arithmetic yourself. A 256-byte buffer accepts exactly 256 bytes, indices 0 to 255. A guard `len > 256` lets `len == 256` through, which is safe for copying `len` bytes but not for writing `buf[len]`. Say which bound you computed.
5. Choose the verdict:
   - CONFIRMED: the shown lines prove the faulty path exists for a value the function can receive.
   - LIKELY: the defect is real on the shown lines, but whether it triggers depends on a caller, macro or configuration not shown.
   - UNCERTAIN: the deciding fact is not shown. This is a correct answer, not a failure; prefer it to a guess.
   - FALSE_POSITIVE: only when a shown line rules the defect out. That line is the decisive line, and you quote it.

Agreement between analysers is not proof: they share blind spots, and three rows on one line are still one claim to check. A candidate reported by a single analyser is not suspect for being alone. Judge the code, not the count.

## Decisive line and evidence quote
- Name exactly one decisive line from the numbered lines of the unit, and copy its text character for character as the evidence quote. Do not quote analyser messages or context, and do not paraphrase.
- If the deciding fact appears only in caller context, use the unit line where that value enters and say in the rationale what the context showed.
- The rationale traces the value in plain words: where it comes from, what bounds it, why that settles it. Do not restate the analyser messages. Do not add a second problem the candidate did not claim; another defect you happen to notice is not part of this verdict.

## SESIP suggestions and exploit note
- Suggest an SFR, level or category only from the values this evaluation lists; omit a suggestion rather than guess one.
- In the exploit note, say in one or two sentences whether an attacker under the stated attacker model could reach this line: a software attacker through a TSFI (a non-secure caller, an external interface, a received message), or a physical attacker only when the attacker model includes one. When the shown code does not tell, say that.
- The exploit note never changes the verdict. A real defect the attacker cannot reach is still CONFIRMED or LIKELY, with the limited reach stated in the note.
