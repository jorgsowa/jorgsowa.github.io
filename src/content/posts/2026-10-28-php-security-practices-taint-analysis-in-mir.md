---
title: "PHP Security Practices, Checked: Inside mir's Taint Analysis"
date: 2026-10-28
description: How a taint analyzer decides that request data reached a dangerous function, with diagrams and real mir output for SQL, HTML, shell, file, header and LLM sinks.
---

This code has an XSS bug:

```php
<?php

function label(string $s): string
{
    return ucfirst(trim($s));
}

$q = $_GET['q'] ?? '';
$title = label($q);
echo "<h1>Results for $title</h1>";
```

<figure class="diagram">
<svg viewBox="0 0 680 145" role="img" aria-labelledby="f1-t">
  <title id="f1-t">Request data flows from $_GET['q'] through $q, label($q) and $title into echo.</title>
  <defs>
    <marker id="f1-h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-flow" d="M0,0 L10,5 L0,10 z"/></marker>
  </defs>
  <text class="label" x="75" y="34" text-anchor="middle">SOURCE</text>
  <text class="label" x="355" y="34" text-anchor="middle">PROPAGATION</text>
  <text class="label" x="620" y="34" text-anchor="middle">SINK</text>
  <path class="rule" d="M180,48 V44 H530 V48"/>
  <rect class="node-src" x="20" y="60" width="110" height="44" rx="4"/>
  <text x="75" y="87" text-anchor="middle">$_GET['q']</text>
  <rect class="node" x="180" y="60" width="70" height="44" rx="4"/>
  <text x="215" y="87" text-anchor="middle">$q</text>
  <rect class="node" x="300" y="60" width="100" height="44" rx="4"/>
  <text x="350" y="87" text-anchor="middle">label($q)</text>
  <rect class="node" x="450" y="60" width="80" height="44" rx="4"/>
  <text x="490" y="87" text-anchor="middle">$title</text>
  <rect class="node-sink" x="580" y="60" width="80" height="44" rx="4"/>
  <text x="620" y="87" text-anchor="middle">echo</text>
  <line class="flow" x1="130" y1="82" x2="179" y2="82" marker-end="url(#f1-h)"/>
  <line class="flow" x1="250" y1="82" x2="299" y2="82" marker-end="url(#f1-h)"/>
  <line class="flow" x1="400" y1="82" x2="449" y2="82" marker-end="url(#f1-h)"/>
  <line class="flow" x1="530" y1="82" x2="579" y2="82" marker-end="url(#f1-h)"/>
  <text class="note" x="75" y="130" text-anchor="middle">client controls it</text>
  <text class="note" x="355" y="130" text-anchor="middle">assignments, calls, string building</text>
  <text class="note" x="620" y="130" text-anchor="middle">interprets it</text>
</svg>
<figcaption>Figure 1. The shape of an injection: a source, a path, a sink.</figcaption>
</figure>

`trim()` and `ucfirst()` change the value, but they don't escape it. In a real project `label()` sits in another file, and the bug is easy to miss in review. Taint analysis follows request data until it reaches a function like `echo`. [mir](/posts/2026-10-18-mir-fast-drop-in-alternative-to-psalm), a PHP static analyzer written in Rust, reports this one and prints the path, source first:

```
src/search.php:10:0 error[MIR0801] TaintedHtml: Tainted HTML output — possible XSS
  = taint flow: $_GET['q'] (line 8) → $q (line 8) → label($q) (line 9) → $title (line 9)
```

Psalm has taint analysis too, but as a separate mode, `psalm --taint-analysis`, which doesn't report type issues, so you have to run it as a second job. In mir it's part of the normal run: the same `vendor/bin/mir src/` that checks types also reports `Tainted*` issues. `--no-taint` turns it off.

All output below is from mir's main branch, which becomes the next release.

## Sources, sinks and escapes

Sources are where untrusted data enters: `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, `$_FILES` names and types, client-controlled `$_SERVER` entries such as `HTTP_*`, `php://input`, `getallheaders()`, and the request objects of Symfony, Laravel and PSR-7.

Sinks are where data is interpreted: `echo`, `$pdo->query()`, `system()`, `file_put_contents()`, `header()`, `unserialize()`, `curl_setopt()` and dozens more.

Escapes make a value safe for some sinks: `htmlspecialchars()`, `escapeshellarg()`, `basename()`, `urlencode()`.

Between a source and a sink, mir follows the value through assignments, string building, arrays and their keys, object properties, closures, generators, and calls to your own functions.

## How a sink decides

When a value reaches a call, mir asks four questions. A report needs a yes to every one of them.

<figure class="diagram">
<svg viewBox="0 0 680 490" role="img" aria-labelledby="f3-t">
  <title id="f3-t">Decision flow: the callee must be a sink, the argument a sink parameter, its type able to carry a payload, and its taint must include the sink's kind. Only then is an issue reported.</title>
  <defs>
    <marker id="f3-h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-edge" d="M0,0 L10,5 L0,10 z"/></marker>
    <marker id="f3-hf" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-flow" d="M0,0 L10,5 L0,10 z"/></marker>
  </defs>
  <rect class="node-src" x="190" y="10" width="200" height="36" rx="18"/>
  <text x="290" y="33" text-anchor="middle">f($value)</text>
  <line class="edge" x1="290" y1="46" x2="290" y2="75" marker-end="url(#f3-h)"/>
  <rect class="node" x="120" y="76" width="340" height="58" rx="4"/>
  <text x="290" y="100" text-anchor="middle">Is the callee a sink?</text>
  <text class="note" x="290" y="120" text-anchor="middle">builtin, PDO method, @taint-sink, summary</text>
  <line class="edge" x1="460" y1="105" x2="509" y2="105" marker-end="url(#f3-h)"/>
  <text class="note" x="470" y="98">no</text>
  <rect class="node-safe" x="510" y="89" width="150" height="32" rx="16"/>
  <text class="small dim" x="585" y="110" text-anchor="middle">not a sink</text>
  <line class="edge" x1="290" y1="134" x2="290" y2="163" marker-end="url(#f3-h)"/>
  <text class="note" x="298" y="153">yes</text>
  <rect class="node" x="120" y="164" width="340" height="58" rx="4"/>
  <text x="290" y="188" text-anchor="middle">Is the argument a sink parameter?</text>
  <text class="note" x="290" y="208" text-anchor="middle">file_put_contents: $filename, not $data</text>
  <line class="edge" x1="460" y1="193" x2="509" y2="193" marker-end="url(#f3-h)"/>
  <text class="note" x="470" y="186">no</text>
  <rect class="node-safe" x="510" y="177" width="150" height="32" rx="16"/>
  <text class="small dim" x="585" y="198" text-anchor="middle">not checked</text>
  <line class="edge" x1="290" y1="222" x2="290" y2="251" marker-end="url(#f3-h)"/>
  <text class="note" x="298" y="241">yes</text>
  <rect class="node" x="120" y="252" width="340" height="58" rx="4"/>
  <text x="290" y="276" text-anchor="middle">Can its type carry a payload?</text>
  <text class="note" x="290" y="296" text-anchor="middle">int, bool, numeric-string, literal: no</text>
  <line class="edge" x1="460" y1="281" x2="509" y2="281" marker-end="url(#f3-h)"/>
  <text class="note" x="470" y="274">no</text>
  <rect class="node-safe" x="510" y="265" width="150" height="32" rx="16"/>
  <text class="small dim" x="585" y="286" text-anchor="middle">safe type</text>
  <line class="edge" x1="290" y1="310" x2="290" y2="339" marker-end="url(#f3-h)"/>
  <text class="note" x="298" y="329">yes</text>
  <rect class="node" x="120" y="340" width="340" height="58" rx="4"/>
  <text x="290" y="364" text-anchor="middle">Does its taint include the sink's kind?</text>
  <text class="note" x="290" y="384" text-anchor="middle">htmlspecialchars() clears html, not sql</text>
  <line class="edge" x1="460" y1="369" x2="509" y2="369" marker-end="url(#f3-h)"/>
  <text class="note" x="470" y="362">no</text>
  <rect class="node-safe" x="510" y="353" width="150" height="32" rx="16"/>
  <text class="small dim" x="585" y="374" text-anchor="middle">escaped</text>
  <line class="flow" x1="290" y1="398" x2="290" y2="427" marker-end="url(#f3-hf)"/>
  <text class="note" x="298" y="417">yes</text>
  <rect class="node-sink" x="120" y="428" width="340" height="48" rx="4"/>
  <text class="hot" x="290" y="450" text-anchor="middle">report Tainted* at the call</text>
  <text class="note" x="290" y="467" text-anchor="middle">with the flow from the source</text>
</svg>
<figcaption>Figure 2. The four checks at every sink.</figcaption>
</figure>

### Taint is a set of kinds

Every value carries the set of sink kinds it's still dangerous for: `html`, `sql`, `shell`, `file`, `header`, `cookie`, `unserialize`, `ssrf`, `ldap`, `xpath`, `callable`, `llm_prompt`, plus `eval` and a catch-all for custom kinds. Data from a source starts with every kind. An escape removes only the kinds it neutralizes. A sink reports when the value still has the sink's own kind.

```php
<?php

$db = new PDO('sqlite::memory:');
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

echo "<p>Hello, $name</p>";
$db->query("SELECT * FROM users WHERE name = '$name'");
```

The `echo` is fine. The query is reported, because HTML escaping is not SQL escaping. `ENT_QUOTES` happens to encode `'` here, but a trailing backslash still escapes the closing quote in MySQL's default mode. A numeric comparison needs no quote at all. And the database stores `&#039;` instead of the name:

```
src/kinds.php:7:0 error[MIR0802] TaintedSql: Tainted SQL query — possible SQL injection
  = taint flow: $_GET['name'] (line 4) → htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') (line 4) → $name (line 4)
```

<figure class="diagram">
<svg viewBox="0 0 640 340" role="img" aria-labelledby="f2-t">
  <title id="f2-t">$_GET['name'] carries all twelve kinds. After htmlspecialchars() the html kind is cleared and the rest remain, so echo is clean and the SQL query is reported.</title>
  <defs>
    <marker id="f2-h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-edge" d="M0,0 L10,5 L0,10 z"/></marker>
    <marker id="f2-hf" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-flow" d="M0,0 L10,5 L0,10 z"/></marker>
  </defs>
  <text x="178" y="36" text-anchor="middle">$_GET['name']</text>
  <text x="338" y="36" text-anchor="middle">htmlspecialchars()</text>
  <line class="edge" x1="234" y1="31" x2="264" y2="31" marker-end="url(#f2-h)"/>
  <text class="note" x="178" y="54" text-anchor="middle">every kind</text>
  <text class="note" x="338" y="54" text-anchor="middle">html cleared</text>
  <g class="small dim" text-anchor="end">
    <text x="140" y="80">html</text>
    <text x="140" y="102">sql</text>
    <text x="140" y="124">shell</text>
    <text x="140" y="146">file</text>
    <text x="140" y="168">header</text>
    <text x="140" y="190">cookie</text>
    <text x="140" y="212">unserialize</text>
    <text x="140" y="234">ssrf</text>
    <text x="140" y="256">ldap</text>
    <text x="140" y="278">xpath</text>
    <text x="140" y="300">callable</text>
    <text x="140" y="322">llm_prompt</text>
  </g>
  <g class="bit-on">
    <rect x="170" y="68" width="16" height="16" rx="3"/>
    <rect x="170" y="90" width="16" height="16" rx="3"/>
    <rect x="170" y="112" width="16" height="16" rx="3"/>
    <rect x="170" y="134" width="16" height="16" rx="3"/>
    <rect x="170" y="156" width="16" height="16" rx="3"/>
    <rect x="170" y="178" width="16" height="16" rx="3"/>
    <rect x="170" y="200" width="16" height="16" rx="3"/>
    <rect x="170" y="222" width="16" height="16" rx="3"/>
    <rect x="170" y="244" width="16" height="16" rx="3"/>
    <rect x="170" y="266" width="16" height="16" rx="3"/>
    <rect x="170" y="288" width="16" height="16" rx="3"/>
    <rect x="170" y="310" width="16" height="16" rx="3"/>
    <rect x="330" y="90" width="16" height="16" rx="3"/>
    <rect x="330" y="112" width="16" height="16" rx="3"/>
    <rect x="330" y="134" width="16" height="16" rx="3"/>
    <rect x="330" y="156" width="16" height="16" rx="3"/>
    <rect x="330" y="178" width="16" height="16" rx="3"/>
    <rect x="330" y="200" width="16" height="16" rx="3"/>
    <rect x="330" y="222" width="16" height="16" rx="3"/>
    <rect x="330" y="244" width="16" height="16" rx="3"/>
    <rect x="330" y="266" width="16" height="16" rx="3"/>
    <rect x="330" y="288" width="16" height="16" rx="3"/>
    <rect x="330" y="310" width="16" height="16" rx="3"/>
  </g>
  <rect class="bit-off" x="330.5" y="68.5" width="15" height="15" rx="3"/>
  <line class="edge" x1="354" y1="76" x2="404" y2="76" marker-end="url(#f2-h)"/>
  <text x="412" y="80">echo <tspan class="dim">→ no issue</tspan></text>
  <line class="flow" x1="354" y1="98" x2="404" y2="98" marker-end="url(#f2-hf)"/>
  <text x="412" y="102">-&gt;query() <tspan class="hot">→ TaintedSql</tspan></text>
</svg>
<figcaption>Figure 3. An escape clears one kind. Each sink checks only its own.</figcaption>
</figure>

mir knows the escapes of PHP and common libraries. `htmlspecialchars()`, `htmlentities()` and `strip_tags()` clear `html`. `escapeshellarg()` clears `shell`. `basename()` clears `file`. `filter_var()` with `FILTER_VALIDATE_INT` clears everything. It also accepts `addslashes()` and `mysqli_real_escape_string()` for `sql`, but bound parameters are the better fix, as the practices below explain.

### Only the dangerous argument counts

mir checks sink parameters, not whole functions. `file_put_contents()` is dangerous when the client picks the file name. Request data written into a log file is fine.

<figure class="diagram">
<svg viewBox="0 0 760 222" role="img" aria-labelledby="f6-t">
  <title id="f6-t">Sink parameters of six calls: file_put_contents $filename, copy $from and $to, mail $additional_headers and $additional_params, curl_setopt value for CURLOPT_URL, unserialize $data, and unserialize with allowed_classes false is not a sink.</title>
  <text class="label" x="20" y="22">SIGNATURE</text>
  <text class="label" x="740" y="22" text-anchor="end">KIND</text>
  <line class="rule" x1="20" y1="32" x2="740" y2="32"/>
  <g class="small">
    <text x="20" y="56">file_put_contents(<tspan class="hot">$filename</tspan>, $data, $flags)</text>
    <text x="20" y="86">copy(<tspan class="hot">$from</tspan>, <tspan class="hot">$to</tspan>)</text>
    <text x="20" y="116">mail($to, $subject, $message, <tspan class="hot">$additional_headers</tspan>, <tspan class="hot">$additional_params</tspan>)</text>
    <text x="20" y="146">curl_setopt($ch, CURLOPT_URL, <tspan class="hot">$value</tspan>)</text>
    <text x="20" y="176">unserialize(<tspan class="hot">$data</tspan>)</text>
    <text x="20" y="206" class="dim">unserialize($data, ['allowed_classes' =&gt; false])</text>
  </g>
  <g class="note" text-anchor="end">
    <text x="740" y="56">file</text>
    <text x="740" y="86">file</text>
    <text x="740" y="116">header, shell</text>
    <text x="740" y="146">ssrf</text>
    <text x="740" y="176">unserialize</text>
    <text x="740" y="206">none</text>
  </g>
</svg>
<figcaption>Figure 4. Highlighted parameters are sinks. The others take any data.</figcaption>
</figure>

```php
<?php

file_put_contents('/var/log/app/search.log', $_GET['q'], FILE_APPEND);
file_put_contents('/var/log/app/' . $_GET['q'], 'hit');

copy('/tmp/upload.bin', $_POST['to']);

mail('admin@example.com', 'Contact', $_POST['message'], 'From: ' . $_POST['email']);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['url']);
curl_setopt($ch, CURLOPT_USERAGENT, $_GET['ua']);

$a = unserialize($_COOKIE['c']);
$b = unserialize($_COOKIE['c'], ['allowed_classes' => false]);
```

```
src/args.php:4:0 error[MIR0800] TaintedInput: Tainted input reaching sink 'file'
  = taint flow: $_GET['q'] (line 4)
src/args.php:6:0 error[MIR0800] TaintedInput: Tainted input reaching sink 'file'
  = taint flow: $_POST['to'] (line 6)
src/args.php:8:0 error[MIR0805] TaintedHeader: Tainted HTTP header — possible header injection or open redirect
  = taint flow: $_POST['email'] (line 8)
src/args.php:11:0 error[MIR0807] TaintedSsrf: Tainted URL — possible server-side request forgery
  = taint flow: $_GET['url'] (line 11)
src/args.php:14:5 error[MIR0800] TaintedInput: Tainted input reaching sink 'unserialize'
  = taint flow: $_COOKIE['c'] (line 14)
```

mir reports 5 of the 7 calls with request data. The log line on line 3, the message body on line 8 and the user agent on line 12 are not reported. Neither is `unserialize()` with `allowed_classes` set to `false`, which can't create objects. `curl_setopt()` is a sink only for `CURLOPT_URL` and `CURLOPT_PROXY`, so the option argument decides whether the value argument is checked.

### Types can make a value safe

The third check uses mir's type inference. A value whose type is `int`, `float`, `bool`, a numeric string or a literal string can't carry an injection payload, whatever its taint says. Validation narrows the type, so it also clears the taint:

```php
<?php

function page(): int
{
    return (int) ($_GET['page'] ?? 1);
}

$db = new PDO('sqlite::memory:');

$id = $_GET['id'];
if (ctype_digit($id)) {
    $db->query("SELECT * FROM posts WHERE id = $id");
}

$dir = $_GET['dir'];
if (in_array($dir, ['asc', 'desc'], true)) {
    $db->query("SELECT * FROM posts ORDER BY created_at $dir");
}

$limit = page() * 20;
$db->query("SELECT * FROM posts LIMIT $limit");

$db->query("SELECT * FROM posts WHERE slug = '" . $_GET['slug'] . "'");
```

```
src/types.php:23:0 error[MIR0802] TaintedSql: Tainted SQL query — possible SQL injection
  = taint flow: $_GET['slug'] (line 23)
```

Inside the `ctype_digit()` branch, `$id` is a numeric string. After the strict `in_array()`, `$dir` is `'asc'|'desc'`. `page()` returns an `int`, and arithmetic always yields a number. Only the last query keeps raw request data. A loose `in_array()` without `true` doesn't narrow and is still reported, because loose comparison treats numeric strings as numbers: `'1e1' == '10'` is true.

### Sinks inside your own functions

In real code a sink usually sits behind a helper, e.g. a repository method or a view function. mir doesn't need annotations for these. It analyzes each function body once and records a summary: which parameters flow to the return value, and which reach a sink inside.

```php
<?php

function render(string $title, string $body): string
{
    return '<h1>' . htmlspecialchars($title) . '</h1>' . $body;
}

function search(PDO $db, string $term, int $limit): array
{
    return $db->query("SELECT * FROM posts WHERE title LIKE '%$term%' LIMIT $limit")->fetchAll();
}

echo render($_GET['title'], '<p>Static body</p>');
echo render('Static title', $_GET['body']);

$db = new PDO('sqlite::memory:');
search($db, $_GET['term'], 10);
```

<figure class="diagram">
<svg viewBox="0 0 680 346" role="img" aria-labelledby="f4-t">
  <title id="f4-t">The body of search() is analyzed once: parameter $term carries a label into the query, so the summary says $term reaches an SQL sink. At the call search($db, $_GET['term'], 10) that is reported; search($db, 'php', 10) is clean.</title>
  <defs>
    <marker id="f4-h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-edge" d="M0,0 L10,5 L0,10 z"/></marker>
    <marker id="f4-hf" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="head-flow" d="M0,0 L10,5 L0,10 z"/></marker>
  </defs>
  <text class="label" x="20" y="24">1 · ANALYZE THE BODY ONCE</text>
  <text class="small dim" x="20" y="50">function search(PDO $db, string $term, int $limit)</text>
  <rect class="node" x="20" y="66" width="140" height="40" rx="4"/>
  <text x="90" y="91" text-anchor="middle">$term #2</text>
  <line class="edge" x1="160" y1="86" x2="199" y2="86" marker-end="url(#f4-h)"/>
  <rect class="node" x="200" y="66" width="210" height="40" rx="4"/>
  <text x="305" y="91" text-anchor="middle">"…LIKE '%$term%'…"</text>
  <line class="edge" x1="410" y1="86" x2="449" y2="86" marker-end="url(#f4-h)"/>
  <rect class="node-sink" x="450" y="66" width="110" height="40" rx="4"/>
  <text x="505" y="91" text-anchor="middle">-&gt;query()</text>
  <text class="note" x="90" y="124" text-anchor="middle">parameter label</text>
  <text class="note" x="305" y="124" text-anchor="middle">string building</text>
  <text class="note" x="505" y="124" text-anchor="middle">sql sink</text>
  <rect class="node-sum" x="160" y="146" width="360" height="36" rx="4"/>
  <text x="340" y="169" text-anchor="middle">summary: #2 ($term) reaches sql</text>
  <line class="rule" x1="20" y1="208" x2="660" y2="208"/>
  <text class="label" x="20" y="234">2 · CHECK EVERY CALL</text>
  <rect class="node" x="20" y="248" width="300" height="38" rx="4"/>
  <text x="170" y="272" text-anchor="middle">search($db, $_GET['term'], 10)</text>
  <line class="flow" x1="320" y1="267" x2="379" y2="267" marker-end="url(#f4-hf)"/>
  <rect class="node-sink" x="380" y="248" width="280" height="38" rx="4"/>
  <text class="hot" x="520" y="272" text-anchor="middle">TaintedSql at this call</text>
  <rect class="node" x="20" y="298" width="300" height="38" rx="4"/>
  <text x="170" y="322" text-anchor="middle">search($db, 'php', 10)</text>
  <line class="edge" x1="320" y1="317" x2="379" y2="317" marker-end="url(#f4-h)"/>
  <rect class="node-safe" x="380" y="298" width="280" height="38" rx="4"/>
  <text class="dim" x="520" y="322" text-anchor="middle">clean: literal string</text>
</svg>
<figcaption>Figure 5. The sink is found in the body. The report goes to the call that passes request data.</figcaption>
</figure>

```
src/summary.php:14:0 error[MIR0801] TaintedHtml: Tainted HTML output — possible XSS
  = taint flow: $_GET['body'] (line 14) → render('Static title', $_GET['body']) (line 14)
src/summary.php:17:0 error[MIR0802] TaintedSql: Tainted SQL query — possible SQL injection
  = taint flow: $_GET['term'] (line 17)
```

`render()` escapes `$title` and returns `$body` as it is, so only the second call is reported. `search()` is reported at the call, not inside the function: a function that builds SQL from a parameter becomes a bug only when someone calls it with untrusted input. `$limit` is an `int`, so it never matters.

For this, one set of kinds per value isn't enough. mir stores taint in 128 bits: nine slots of 14 kinds. The first slot is taint from real sources, the one that triggers reports. While a body is analyzed, each of the first eight parameters gets its own slot, called a label. If `htmlspecialchars($title)` clears `html` in the slot of `$title`, the summary remembers that `$title` is safe for HTML, and that `$body` isn't.

<figure class="diagram">
<svg viewBox="0 0 680 118" role="img" aria-labelledby="f5-t">
  <title id="f5-t">A taint value has nine slots of fourteen kinds: one for sources and eight for parameter labels.</title>
  <text class="label" x="20" y="22">ONE TAINT VALUE · 9 SLOTS × 14 KINDS</text>
  <rect class="node-sink" x="20" y="34" width="70" height="40"/>
  <text x="55" y="59" text-anchor="middle">src</text>
  <rect class="node" x="90" y="34" width="70" height="40"/>
  <text class="dim" x="125" y="59" text-anchor="middle">#1</text>
  <rect class="node" x="160" y="34" width="70" height="40"/>
  <text class="dim" x="195" y="59" text-anchor="middle">#2</text>
  <rect class="node" x="230" y="34" width="70" height="40"/>
  <text class="dim" x="265" y="59" text-anchor="middle">#3</text>
  <rect class="node" x="300" y="34" width="70" height="40"/>
  <text class="dim" x="335" y="59" text-anchor="middle">#4</text>
  <rect class="node" x="370" y="34" width="70" height="40"/>
  <text class="dim" x="405" y="59" text-anchor="middle">#5</text>
  <rect class="node" x="440" y="34" width="70" height="40"/>
  <text class="dim" x="475" y="59" text-anchor="middle">#6</text>
  <rect class="node" x="510" y="34" width="70" height="40"/>
  <text class="dim" x="545" y="59" text-anchor="middle">#7</text>
  <rect class="node" x="580" y="34" width="70" height="40"/>
  <text class="dim" x="615" y="59" text-anchor="middle">#8</text>
  <path class="rule" d="M92,82 V86 H648 V82"/>
  <text class="note" x="55" y="102" text-anchor="middle">reported</text>
  <text class="note" x="370" y="102" text-anchor="middle">parameter labels, kept in the summary</text>
</svg>
<figcaption>Figure 6. An escape clears a kind in every slot, so a parameter remembers what was escaped.</figcaption>
</figure>

Summaries cover more than return values: a constructor that stores a parameter in a property, a setter, a by-reference parameter the function writes into, values a generator yields.

### Declaring your own

Functions without a body, such as interface methods or SDK calls mir can't see into, need annotations. They follow Psalm's, and each also accepts the `@psalm-` prefix, so existing `@psalm-taint-*` annotations keep working:

| Annotation | Meaning |
| --- | --- |
| `@taint-source` | The return value is user-controlled |
| `@taint-sink <kind> $param` | Tainted data passed to `$param` is reported |
| `@taint-escape <kind>` | The return value is safe for `<kind>` sinks |
| `@taint-unescape <kind>` | The return value is dangerous again for `<kind>`, for example after `html_entity_decode()` |
| `@psalm-flow ($a) -> return` | Taint flows from `$a` to the return value |

Use `@taint-source` for data that isn't from the request but is still attacker-controlled: messages from a queue, rows imported from a partner's CSV, a webhook payload.

## Five practices, and what checks them

### 1. Treat all request data as untrusted

Every part of the request is controlled by the client: headers, cookies, the uploaded file name, the `Host` header. Validation in the browser doesn't count; anyone can send a request with `curl`. Figure 1 is the common mistake: trusting a value because a helper touched it. Normalizing a value with `trim()` or `strtolower()` doesn't make it safe.

### 2. Escape output for its context

For HTML, escape at the moment of output, with the flags that cover quotes and broken UTF-8:

```php
echo htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

Since PHP 8.1 `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401` is the default, but set them explicitly if you still support PHP 8.0 or older. In templates, use the escaping your engine does by default: Twig and Blade's `{{ }}` both escape. Their raw output, `|raw` and `{!! !!}`, is where XSS comes back.

HTML escaping is right only for HTML text and quoted attributes. A value inside a `<script>` block, a `style` attribute or an `href` needs a different encoding, and `htmlspecialchars()` doesn't stop `javascript:alert(1)` in a link. If your project has its own helper, tell mir what it escapes:

```php
/**
 * @taint-escape html
 */
function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
```

### 3. Bind values, allowlist identifiers

Escaping functions for SQL are easy to get wrong: a missing quote around the value, a different connection charset, a number that isn't quoted. Bound parameters remove the problem, because the value never becomes part of the SQL text:

```php
$stmt = $db->prepare('SELECT * FROM posts WHERE title LIKE ? LIMIT ?');
$stmt->bindValue(1, '%' . $term . '%');
$stmt->bindValue(2, $limit, PDO::PARAM_INT);
$stmt->execute();
```

Column names, table names and sort directions can't be bound. Check them against a fixed list with a strict comparison, `match` or a strict `in_array()`, as in the type example above. Cast numbers with `(int)`.

### 4. Keep request data out of paths, commands, headers and `unserialize()`

```php
<?php

$name = $_GET['file'];
readfile('/var/www/uploads/' . $name);
readfile('/var/www/uploads/' . basename($name));

system('convert ' . $_POST['image'] . ' out.png');
system('convert ' . escapeshellarg($_POST['image']) . ' out.png');

header('Location: ' . $_GET['next']);

$prefs = unserialize($_COOKIE['prefs']);
$prefs = json_decode($_COOKIE['prefs'], true);

$avatar = file_get_contents($_POST['avatar_url']);
```

```
src/files.php:4:0 error[MIR0800] TaintedInput: Tainted input reaching sink 'file'
  = taint flow: $_GET['file'] (line 3) → $name (line 3)
src/files.php:7:0 error[MIR0803] TaintedShell: Tainted shell command — possible command injection
  = taint flow: $_POST['image'] (line 7)
src/files.php:10:0 error[MIR0805] TaintedHeader: Tainted HTTP header — possible header injection or open redirect
  = taint flow: $_GET['next'] (line 10)
src/files.php:12:9 error[MIR0800] TaintedInput: Tainted input reaching sink 'unserialize'
  = taint flow: $_COOKIE['prefs'] (line 12)
src/files.php:15:10 error[MIR0800] TaintedInput: Tainted input reaching sink 'file'
  = taint flow: $_POST['avatar_url'] (line 15)
```

Every unsafe line is reported, and none of the safe variants. How to fix each one:

- File paths: the client can send `../../etc/passwd` as the name. Use `basename()` when the value should be a plain name, or resolve it with `realpath()` and check that it starts with the base directory plus a trailing `/`. Better, store uploads under a generated name.
- Shell commands: Avoid the shell when a PHP function or library does the job. Otherwise `escapeshellarg()` every argument, or pass the command to `proc_open()` as an array, which since PHP 7.4 runs the program without a shell.
- Headers: PHP blocks line breaks in `header()`, but a tainted `Location` is still an open redirect. Redirect only to relative paths or hosts on an allowlist.
- Deserialization: `unserialize()` on client data can construct any class the autoloader knows and run its magic methods. Use `json_decode()`, or at least `['allowed_classes' => false]`.
- Outgoing requests: A URL from the request lets the client make your server fetch `http://169.254.169.254/` or an internal admin panel. Fix the scheme and host in code and `urlencode()` what you append. mir doesn't report a URL that starts with a literal `https://host/`.

### 5. Treat LLM prompts as a sink

More PHP applications send user text to a language model. Prompt injection is the SQL injection of that code: the user's text can override your instructions, leak the system prompt or trigger tool calls. No escaping function fixes it, but the data flow is the same, so mark the method that sends the prompt:

```php
<?php

interface LanguageModel
{
    /**
     * @taint-sink llm_prompt $prompt
     */
    public function complete(string $prompt): string;
}

function summarize(LanguageModel $llm): string
{
    return $llm->complete('Summarize this review: ' . $_POST['review']);
}
```

```
src/llm.php:13:11 error[MIR0804] TaintedLlmPrompt: Tainted LLM prompt — possible prompt injection
  = taint flow: $_POST['review'] (line 13)
```

The annotation on the interface covers every implementation. There is no escape for this kind, so the fix is in how you call the model. Keep user content apart from instructions in the API call. Don't give the model tools it doesn't need. Treat its answer as untrusted output too. Once you've reviewed a call, suppress it with `@psalm-suppress TaintedLlmPrompt` and a comment saying why.

## On a real framework

I ran mir on Laravel framework v13.36.0. Two reports lead to the same function:

```
src/Illuminate/Foundation/Http/Middleware/PreventRequestForgery.php:189:51 error[MIR0800] TaintedInput: Tainted input reaching sink 'unserialize'
  = taint flow: $request->header('X-XSRF-TOKEN') (line 187) → $header (line 187)
src/Illuminate/Cookie/Middleware/EncryptCookies.php:91:25 error[MIR0800] TaintedInput: Tainted input reaching sink 'unserialize'
  = taint flow: $request->cookies (line 85) → $cookie (line 85)
```

The `X-XSRF-TOKEN` header and the cookies go to `Encrypter::decrypt()`, which calls `unserialize()` when its second argument is true. Here it is `static::$serialize`: `false` by default, but a mutable static property, so mir can't prove it stays off. The payload is also encrypted and authenticated with `APP_KEY`.

This is the path behind CVE-2018-15133. Before Laravel 5.6.30, cookies were serialized by default, and anyone who knew the `APP_KEY` could send a payload in `X-XSRF-TOKEN` and get remote code execution. The flow mir reports is real. Today only a default and a secret keep it safe. Have that in mind before you set `$serialize = true` or commit an `.env` file.

## Try it

Paste any of the examples into the [playground](https://jorgsowa.github.io/mir/playground), or run it on your project:

```sh
composer require --dev miropen/mir-php
vendor/bin/mir src/
```

The [taint annotations](https://jorgsowa.github.io/mir/reference/docblock/) and every security issue are documented at [jorgsowa.github.io/mir](https://jorgsowa.github.io/mir/). If mir misses a flow or reports a safe one, open an [issue](https://github.com/jorgsowa/mir/issues) with a short code sample.
