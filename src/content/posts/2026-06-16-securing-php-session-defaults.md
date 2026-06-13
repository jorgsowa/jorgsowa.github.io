---
title: Harden Your Session Cookie Configuration in PHP, PHP 8.6 RFC
date: 2026-06-16
description: How I got an RFC merged into php-src that tightens session cookie defaults (use_strict_mode, httponly, and SameSite) after years of them lagging behind security recommendations.
---

In 2016, PHP internals [rejected a proposal](https://wiki.php.net/rfc/session-use-strict-mode) to enable `session.use_strict_mode` by default. This year, the same change passed without a single vote against, along with two more secure settings.

## The RFC

The full RFC is at [wiki.php.net/rfc/session_security_defaults](https://wiki.php.net/rfc/session_security_defaults). It flips three defaults:

- `session.use_strict_mode`: `false` → `true`
- `session.cookie_httponly`: `false` → `true`
- `session.cookie_samesite`: `""` → `"Lax"`

Session cookie defaults in PHP have been insecure for a long time, plainly behind the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), which has recommended against these defaults for years. There was a GitHub issue sitting open for years, written by someone who lost their site to an attack the defaults made possible ([#7913](https://github.com/php/php-src/issues/7913)).

The original proposal covered only two values. Initially I was waiting for the author to write to the internals list. A few months passed, nothing moved, and I forgot about it. I came back to it this year, added `cookie_samesite`, and pushed it through.

The implementation is a handful of lines. Writing an RFC that doesn't get rejected is a bigger task, especially with the 2016 rejection on record. The outcome was surprising to me. No heated discussion. No votes against. Everything passed.

## Why these three settings matter

`use_strict_mode` blocks session fixation. PHP normally accepts any session ID the client sends, including one an attacker injected before the user logged in. Strict mode rejects unknown IDs and issues a fresh one.

`cookie_httponly` keeps JavaScript from reading the session cookie. It doesn't stop XSS, but it breaks the most common XSS payload: `document.cookie` theft.

`cookie_samesite=Lax` tells the browser not to send the session cookie on cross-site POST requests, which cuts off the most common CSRF vector without breaking link navigation or GET-based OAuth flows.

None of this is new. The OWASP cheat sheet has said the same things for years.

## Existing applications

These defaults only apply to new setups. If you're running an existing application, your `php.ini` already has values locked in, and the RFC doesn't change them.

Check your actual values. Don't assume a recent PHP version means secure session config. Add this to your `php.ini`:

```ini
session.use_strict_mode = On
session.cookie_httponly = On
session.cookie_samesite = Lax
```

Or set them at runtime, before `session_start()`:

```php
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
session_start();
```

Session config is one of those places where you can be running on insecure settings from a five-year-old setup and have no idea.

## How I got here and what's next

I started contributing to php-src a few years ago. Early commits were simple: removing dead code, cleaning up deprecated features. My first commit in `ext/session` was exactly that, removing dead code from `session_decode` and `session_encode` functions ([#13796](https://github.com/php/php-src/pull/13796)).

The more I dug into the session extension, the more I found to fix. My first serious attempt was a bug I was convinced was a security vulnerability, a broken session GC triggered by a specific set of values ([#15284](https://github.com/php/php-src/pull/15284)). I tracked it down through manual calculation, before AI tooling was widespread, which felt satisfying. It wasn't accepted as a security issue, so I opened a pull request and it got fixed that way.

I'm at 21 pull requests in `ext/session` now, with two more in review. The goal across all of them is the same: make things predictable and secure, in ways a developer can reason about, without tripping over behavior that's only there because nobody cleaned it up in the last 20 years.

Outside of php-src, I'm also designing a tool for auditing INI settings. `php.ini` has a lot of settings where the default was fine in 2005 and is a liability now. I'm building it at [php-ini-audit](https://github.com/jorgsowa/php-ini-audit) and will write about it here when it's ready.
