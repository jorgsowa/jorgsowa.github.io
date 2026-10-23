---
title: "mir: A Fast, Drop-In Alternative to Psalm, Written in Rust"
date: 2026-10-18
description: Why I built mir, a PHP static analyzer in Rust that reads your existing Psalm config, baseline and annotations, and checks Laravel and Symfony in under 2 seconds.
---

## Why I built another PHP static analyzer

I have used Psalm for years and contributed to it. It changed how I write PHP, and it raised the bar for a lot of PHP code. What I wanted next was the same analysis, fast enough to run all the time.

So in April 2026 I started **mir**, a PHP static analyzer written in Rust. It reads your existing `psalm.xml`, baseline and `@psalm-*` annotations. On the same laptop, it checks Laravel and Symfony in 0.7 to 2 seconds. Psalm needs 37 to 54 seconds and 3 to 4 GB of memory.

This post covers what **Psalm** gave PHP, how **mir** stays consistent with it, the benchmark numbers, how to switch, and where mir still has gaps.

## What Psalm gave PHP

Psalm made strict typing practical in PHP years before the language could express it. Started at Vimeo, it gave PHP developers:

- **Types richer than PHP's own:** generics with `@template`, `list<T>`, `non-empty-string`, `class-string`, literal types and array shapes, all written in docblocks.
- **An ecosystem that speaks them.** PHPStan reads the same type syntax, and PhpStorm has understood `@psalm-` annotations since [2020.3](https://blog.jetbrains.com/phpstorm/2020/12/phpstorm-2020-3-release/).
- **Security checks in everyday CI.** Taint analysis follows user input to SQL, HTML and shell sinks on every build.
- **Purity and immutability as checked contracts**, through `@psalm-pure` and `@psalm-immutable`.

Large projects such as Symfony run Psalm in CI. Many libraries ship precise docblock types because of it. That work is worth keeping.

## Consistent with Psalm, by design

**mir** doesn't invent a new dialect. It builds on everything above:

- The same type syntax and the same `@psalm-*` annotations.
- The same `psalm.xml`, baseline file and error levels 1 to 8.
- The same issue names where a check exists in both, such as `InvalidArgument`, `UndefinedMethod` and `TaintedSql`. Your suppressions keep matching.

The annotations your team has written over the years mean the same thing to mir.

## Time for faster tools

Static analysis pays off when it runs constantly: on every save, in the editor, on every push. At 40 to 50 seconds per run, it runs once before a push, and CI waits for it.

Psalm is written in PHP, which caps how fast a full run can be. A compiled analyzer that runs on every core removes that cap. That was the idea behind mir.

## Meet mir

**mir** is a PHP static analyzer written in Rust that follows Psalm's type model and config format. It is MIT licensed.

- **Parallel and incremental.** Files are analyzed across all CPU cores, and a content-hash cache skips unchanged files on the next run.
- **PHP 7.4 to 8.6**, with version-aware stubs for 57 extensions taken from **JetBrains' phpstorm-stubs**.
- **140+ diagnostic rules:** type mismatches, undefined symbols, nullability, generics, inheritance and signature checks, dead code, and taint analysis.
- **One binary.** No PHP runtime, no Composer autoloader and no extensions needed to run it.

The analysis has two passes. First, mir collects every class, function and constant. Then it analyzes function bodies in parallel, one file per worker, with full type inference and narrowing.

## Benchmarks: 19 to 82 times faster, with a fifth of the memory or less

I ran both tools on the same laptop against two large real-world codebases, Symfony and Laravel. Each cell is the fastest of the runs, which favors the slower tool.

![Wall time and peak memory for mir 0.88.0 vs Psalm 6.20.0 on Laravel and Symfony, cold and warm runs. mir: 0.66 s / 253 MB (Laravel cold), 0.68 s / 239 MB (Laravel warm), 2.02 s / 626 MB (Symfony cold), 1.68 s / 646 MB (Symfony warm). Psalm: 54.3 s / 4.2 GB, 37.0 s / 3.3 GB, 38.8 s / 3.5 GB, 43.0 s / 4.1 GB.](/images/mir-benchmarks.png)

Cold means no cache. Warm means a second run on unchanged code with the cache from the previous run. Memory is peak resident memory. For Psalm it is the sum of the main process and its 9 workers.

In CI, that is the difference between a check you wait for and one that finishes before the test job starts. Locally, it means running the analyzer on every save instead of before every push.

### How I measured

- **Symfony** at commit `b47221ac` (16 October 2026), dependencies installed. Both tools used Symfony's own unmodified `psalm.xml`: `src/`, tests excluded, error level 5, with its baseline.
- **Laravel** framework v13.36.0, `src/`, 1,742 files. Psalm ran at error level 1 with `findUnusedCode` off; mir ran with its defaults.
- Three runs per mir cell and two per Psalm cell. Wall time and memory came from polling the whole process tree every 100 ms.
- Psalm's cache didn't make full runs faster here. Psalm's `--diff` mode, which re-checks only changed files, was not measured.

## Switching takes two commands

```bash
composer require --dev miropen/mir-php
vendor/bin/mir src/
```

The Composer package downloads a prebuilt binary for your platform. Everything you already set up for Psalm keeps working:

- **Config:** if there is no `mir.xml`, mir reads `psalm.xml`, including `projectFiles`, `ignoreFiles` and issue handlers.
- **Baselines:** `psalm-baseline.xml` is found automatically. `--set-baseline` and `--update-baseline` work as in Psalm.
- **Annotations:** `@psalm-suppress`, `@psalm-pure`, `@psalm-immutable`, `@psalm-param`, `@psalm-return` and every other `@psalm-` tag are accepted, along with Psalm and PHPStan type syntax. `@phpstan-ignore` works too.
- **Strictness:** `errorLevel="1"` to `"8"` uses Psalm's own per-issue levels.
- **Plugins:** mir has a Rust plugin API modeled on Psalm's event handlers. Existing Psalm plugins written in PHP, such as the PHPUnit plugin, run through a bridge that starts a PHP subprocess.

You can run both tools side by side in CI for a while and compare the results before you remove Psalm.

## Try it

- **In the browser:** the [playground](https://jorgsowa.github.io/mir/playground) runs mir compiled to WebAssembly. Paste code and see the diagnostics without installing anything.
- **In a project:** `composer require --dev miropen/mir-php`, or `cargo install mir-php`.
- **In CI:** the GitHub Action:

```yaml
- uses: jorgsowa/mir-action@v1
  with:
    path: src
```

Docs, every rule and the config reference are at [jorgsowa.github.io/mir](https://jorgsowa.github.io/mir/). The source is on [GitHub](https://github.com/jorgsowa/mir).

## Where mir stands today

mir is at version 0.88. It hasn't reached 1.0, and some things are still missing:

- **Not every Psalm rule is implemented**, and some issue names differ. Expect a different issue list on your first run.
- **PHP 8.5 and 8.6 are parsed in full.**
- **Psalm PHP plugins need PHP and Psalm installed** for the bridge. Native Rust plugins don't.

If you try it on your codebase, I'd like to hear what it gets wrong. Open an issue on [GitHub](https://github.com/jorgsowa/mir/issues) with a short code sample.
