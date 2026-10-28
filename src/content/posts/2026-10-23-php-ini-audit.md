---
title: "php-ini-audit: Check What Your PHP Actually Runs With"
date: 2026-10-23
description: A static, read-only security audit for php.ini, PHP-FPM pools, .user.ini and .htaccess, in the browser or the CLI. PHP2Shell showed why you need one.
---

On 21 October 2026 PHP released 8.2.35, 8.3.36, 8.4.27 and 8.5.12 to fix PHP2Shell: two unauthenticated remote code execution bugs, CVE-2026-109618 and CVE-2026-109619. Upgrading is the fix. Until you can upgrade, the advice is about configuration: turn off `session.upload_progress`, keep `post_max_size` small, decide what to do with `memory_limit`.

That leads to two questions for every server. Which PHP version runs there? And what values does it actually use? The second one is harder than it looks. I have been building [php-ini-audit](https://github.com/jorgsowa/php-ini-audit) to answer it.

## Your php.ini is not your config

The value PHP uses for a request is assembled from several layers:

1. Compiled-in defaults.
2. `php.ini`.
3. `conf.d/*.ini`, in alphabetical order.
4. The PHP-FPM pool, with `php_value` and `php_admin_value`.
5. `.user.ini` or `.htaccess`, per directory.
6. `ini_set()` in the application.

Each layer has its own traps. The CLI and FPM read different `php.ini` files, so `php -i` in a shell doesn't tell you what the web server runs with. `.user.ini` can't change `PHP_INI_SYSTEM` directives such as `disable_functions`, and PHP ignores the attempt silently. Directive names are case-sensitive, and PHP ignores unknown names too, so `session.cookie_secur = 1` is a no-op.

A directive that isn't set anywhere falls back to the compiled-in default, not to the value in `php.ini-production`. Some of those defaults are insecure: `display_errors = 1`, `enable_dl = 1`, `cgi.fix_pathinfo = 1`, `session.use_strict_mode = 0`, `session.cookie_httponly = 0`. The official Docker images ship `php.ini-production` but no `php.ini`, so they run on exactly these defaults.

## Least functionality

NIST SP 800-53 has a control for this, CM-7 Least Functionality: configure the system to provide only the capabilities it needs, and disable or restrict everything else. The enhancement CM-7(1) adds a periodic review to find and remove what became unnecessary.

`session.upload_progress` is the textbook case. It has been enabled by default since PHP 5.4. On every multipart POST that contains a field named after `session.upload_progress.name`, PHP writes upload state into the session, before any script runs. Almost no application uses it today, because progress bars are done in JavaScript with `XMLHttpRequest` or `fetch`. Yet it is on in nearly every installation.

PHP2Shell used it. CVE-2026-109619 keeps request state alive after a fatal error, and the next request on the same worker uses it. Session upload progress is one confirmed path to that state. The mitigation is one line:

```ini
session.upload_progress.enabled = 0
```

File uploads keep working. Only the progress tracking in `$_SESSION` stops. Under CM-7 this setting would have been off years ago, and the confirmed path would not exist on that server. It doesn't fix the bug, other variants remain, but it removes attack surface that brought nothing.

Set it in `php.ini` or in the FPM pool, then restart every worker. php-ini-audit reports `.user.ini` as too late for this setting, because it is applied after the request body is parsed.

The same principle runs through many php-ini-audit rules: `disable_functions` for command execution you don't call, `allow_url_fopen`, `enable_dl`, FFI, Xdebug in production, `opcache.restrict_api`, the PHP-FPM status page. If the application doesn't use it, it should be off.

## What php-ini-audit is

php-ini-audit is a static, read-only audit of PHP configuration. It reads `php.ini`, `conf.d`, PHP-FPM pools, `.user.ini`, `.htaccess` and `phpinfo()` output. It never runs `php`, a shell or any other process, and never opens a network connection. A test walks the source tokens and fails if such a call appears.

It parses files the way PHP does: `#` is not a comment since PHP 7, unquoted `None` means empty, and `128M` or `0x10` follow `zend_ini_parse_quantity()`. Then it layers them in PHP's order and evaluates every rule against the effective configuration of each SAPI: fpm, apache2, cgi, litespeed or cli. Each finding points to the file and line that set the value, or says `at built-in default`.

It runs on PHP 7.4 and newer with core extensions only. MIT licensed.

## What it checks

There are 130 rules. A few examples by category:

- Code execution: missing `disable_functions` entries and known bypasses, `auto_prepend_file`, FFI, `.` in `include_path`.
- Filesystem: `open_basedir` unset, set to `/`, or matching by prefix. `/var/www` also allows `/var/www-old`; only `/var/www/` restricts it to the directory.
- Information disclosure: `display_errors`, `expose_php`, function arguments in stack traces.
- Session: missing `Secure`, `HttpOnly` or `SameSite`, session IDs outside cookies, session files in a shared directory. I wrote about the [session defaults RFC](/posts/2026-06-16-securing-php-session-defaults) earlier.
- Resources: `memory_limit`, `post_max_size`, `max_input_vars`, multipart body parts, PCRE limits.
- PHP-FPM: workers running as root, a listener on a network interface, a world-writable socket, a public status page.
- CGI and `.htaccess`: `cgi.fix_pathinfo`, `cgi.force_redirect`, handlers that run non-PHP files as PHP.
- Hygiene: misspelled directives with the closest match, deprecated and obsolete directives, overrides PHP ignores.

`php-ini-audit rules` lists all of them. The [rules reference](https://jorgsowa.github.io/php-ini-audit/rules.html) has the description and fix for each.

## Known vulnerabilities

php-ini-audit reads the PHP version from files, never by running `php -v`: `php_version.h`, the Alpine or dpkg package database, Homebrew links. You can also pass `--php-version`.

Many PHP vulnerabilities need a feature to be enabled. CVE-2024-4577 needs php-cgi on Windows. CVE-2024-9026 needs `catch_workers_output` in an FPM pool. For about 30 CVEs like these, php-ini-audit checks both the version and the configuration, and reports the CVE only when both match. Every other disclosed CVE fixed in a later release is listed in one summary warning.

Example for a server on PHP 8.4.26:

```ini
memory_limit = 128M
post_max_size = 512M
session.upload_progress.enabled = On
open_basedir = /var/www
session.cookie_secur = 1
```

Run:

```sh
php-ini-audit --php-version 8.4.26 --sapi fpm php.ini
```

Output (shortened):

```
CRITICAL CVE-2026-109618 Remote code execution after an out-of-memory error
         PHP 8.4.26 is affected (fixed in 8.4.27); memory_limit = 128M lets a request
         run into the out-of-memory path; post_max_size = 512M accepts large request bodies
CRITICAL CVE-2026-109619 Remote code execution through stale request state
         PHP 8.4.26 is affected (fixed in 8.4.27); session.upload_progress.enabled is On
MEDIUM   CFG-003        Unknown directive resembling a known one
         unknown directive 'session.cookie_secur'; did you mean 'session.cookie_secure'?
LOW      FS-003         open_basedir entries match by prefix
         entries without trailing separator: /var/www
```

Every finding also has a `fix:` line. After you close both PHP2Shell paths, the CVEs stay in the report with medium confidence. That's on purpose: the configuration reduces exposure, it doesn't patch the binary.

## In the browser

The [browser scanner](https://jorgsowa.github.io/php-ini-audit/scan.html) runs the same code in WebAssembly with php-wasm. Nothing is uploaded.

Paste `phpinfo()` output, `php -i`, `php.ini`, an FPM pool, `.user.ini` or `.htaccess`. It detects the input type and the SAPI. `phpinfo()` from the web server gives the best result, because it contains the effective values after every layer and the exact PHP version. The page also has a small script that prints only what the scanner needs and masks values that look like credentials.

## In the CLI and CI

```sh
composer global require jorgsowa/php-ini-audit
```

```sh
php-ini-audit                                # every PHP installation on this host
php -i | php-ini-audit --phpinfo -           # values a running PHP reports
php-ini-audit --root /mnt/container-rootfs   # extracted image or mounted disk
php-ini-audit --format sarif -o report.sarif # GitHub code scanning
php-ini-audit --fail-on high                 # exit 1 on high or critical findings
```

Without arguments it searches the usual locations on Debian, RHEL, Alpine, Homebrew, cPanel, Plesk, the official Docker images and Windows. `--root` audits a container image before it ships. Output formats are text, JSON, SARIF and Markdown. For a single file to copy onto a server, build the phar with `php -d phar.readonly=0 scripts/build_phar.php`.

Running it on a schedule and in CI with `--fail-on` is the periodic review CM-7(1) asks for.

## Limits

php-ini-audit is static. It doesn't see `ini_set()` calls in the application.

Debian and Ubuntu backport security fixes without changing the upstream version string. For distribution builds the version has low confidence, so check the package changelog.

It's at 0.1.0. Rules, severities and the output may change.

## Try it

Scan one of your servers in the [browser](https://jorgsowa.github.io/php-ini-audit/scan.html) or with the CLI. The source is on [GitHub](https://github.com/jorgsowa/php-ini-audit). If a rule is wrong or missing, open an [issue](https://github.com/jorgsowa/php-ini-audit/issues) with the config that triggers it.
