# GGUF Fuzzing Project

This project tests the GGUF file reader from
[llama.cpp](https://github.com/ggml-org/llama.cpp) by throwing large
numbers of broken, weird, and randomly mutated files at it and watching for
crashes, hangs, or anything the code does not handle correctly. It is a
portfolio project for AI red team work, and it tries to be completely
honest about what it found and what it did not find.

## What is a fuzzer?

A fuzzer is a program that automatically generates lots of unusual or
broken inputs and feeds them to another program, to see if any of them
break it. Instead of a person sitting down and thinking up test cases by
hand, the fuzzer makes thousands or millions of small changes to a starting
file (flipping bits, changing numbers, cutting off the end, and so on) and
tries every version. If the target program crashes, hangs, or does
something it should not, that is a finding worth looking at.

## What does "coverage-guided" mean?

A coverage-guided fuzzer keeps track of which lines and branches of the
target program's code get run for each input it tries. If a mutated input
makes the program run a piece of code it has never run before, the fuzzer
treats that input as interesting and keeps mutating it further, instead of
just generating random bytes forever. This makes the fuzzer much better at
reaching deep, unusual parts of the code than pure random testing would be,
because it is not just guessing blindly, it is following a trail of "this
change reached somewhere new."

## What was tested

The target is `gguf_reader.py`, a pure-Python file that llama.cpp uses to
read `.gguf` model files (the file format that stores AI model weights).
This file has been hardened three separate times recently against known
weaknesses (bad alignment values, tensors with too many dimensions, and
oversized length fields). Both of those fixes are already in place. So this
project is not trying to rediscover bugs that are already fixed. It is
asking a different question: do those fixes actually hold up under
sustained, automated, adversarial testing, and is there anything nearby
that the fixes missed?

The tool used to do the fuzzing is called
[Atheris](https://github.com/google/atheris), a coverage-guided fuzzer for
Python built by Google, based on the same engine (libFuzzer) that is used
to fuzz C and C++ code.

## What we found

We found one real problem: a small file, about 100 bytes, can make the
reader spend 20 to 40 seconds of pure CPU time doing essentially nothing
useful, without ever raising an error. The reader has a safety check that
stops it from being told there are more than about a billion items in a
list, which correctly prevents it from trying to allocate a huge amount of
memory. But that check does not stop a smaller, still-huge number (we saw
values around 7 to 13 million) from making the code loop through that many
items one at a time in plain Python, which is slow. The result is a file
that is not dangerous in the sense of crashing anything or corrupting
memory, but that could tie up a service for a long time if it accepts
untrusted `.gguf` files without its own timeout. Full technical detail,
including the exact bytes that trigger it, is in `FINDINGS.md`.

We did not find any memory-safety crashes, and we did not find any way to
get past the alignment check, the dimension-count check, or the other
length checks. Those all held up.

## Why this is honest, not just optimistic

It would be easy to write "no crashes found" and imply that means the code
is safe. That would be misleading, so we did not do that. `FINDINGS.md`
spells out, in plain terms, what a clean fuzzing run does and does not
prove: it does not prove there are no more bugs, it does not test the C++
code that also reads GGUF files (only the Python reader), and covering 85
to 89 percent of the code's lines is not the same as testing every
combination of values that could reach those lines. We also built a
specific test (`tests/test_guards.py`) that proves the fuzzer can actually
reach the parts of the code we care about, by constructing bad files by
hand and checking the reader rejects them correctly. Without that test, a
clean fuzzing run would be meaningless, because it could just mean the
fuzzer never got anywhere near the interesting code.

## How the pieces fit together

- `vendor/` -- a frozen copy of the exact version of the GGUF reader we
  tested, so the line numbers in this write-up never drift out of date.
  `vendor/COMMIT.txt` records exactly where it came from.
- `src/make_corpus.py` -- builds a handful of small, valid `.gguf` files by
  hand, so the fuzzer has real starting points instead of wasting almost
  all its time failing the very first check (is this even a GGUF file?).
- `src/fuzz_gguf.py` -- the actual fuzzing harness: feeds candidate bytes
  to the reader, catches the errors we expect the reader to raise on purpose,
  and lets anything else through so the fuzzer notices it.
- `src/run_campaign.sh` / `src/resume_campaign.sh` -- scripts that run the
  fuzzer for a long stretch, automatically restarting it every time it
  finds something (because the fuzzer stops itself the moment it finds a
  problem, by design).
- `tests/test_guards.py` -- hand-built proof that the reader's safety
  checks are reachable and actually work.
- `tests/test_instrumentation.py` -- proof that the fuzzer is really
  measuring code coverage in the target and not just generating random
  bytes while looking busy.
- `FINDINGS.md` -- the full write-up: what we tested, what we found, the
  exact numbers from the runs we did, and an honest list of what this work
  does not prove.
- `logs/` -- the raw output from every run described in this project, so
  every number in `FINDINGS.md` can be checked against a real log file.

## Running it yourself

```
cd /home/kali/director/projects/gguf-fuzzing
source .venv/bin/activate
python3 src/make_corpus.py               # build the seed files
python3 -m pytest tests/ -v              # run the guard and instrumentation tests
python3 src/fuzz_gguf.py corpus/ -atheris_runs=5000   # a short fuzzing run
```
