// Turns raw collector output into page data (src/data/php-sbom.json) and CycloneDX files (public/sbom/).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, basename } from 'node:path';

const [rawDir, root = '.'] = process.argv.slice(2);
if (!rawDir) {
  console.error('usage: node build.mjs <raw-dir> [site-root]');
  process.exit(1);
}

const COLLECTED = '2026-10-29';

const BUILDS = [
  {
    id: 'docker-debian',
    label: 'Official Docker image',
    variant: 'php:8.5-cli',
    distro: { type: 'deb', namespace: 'debian' },
    install: 'docker pull php:8.5-cli',
    about: 'Built from the php.net source on Debian 13 and installed to /usr/local. {system} Debian packages provide the libraries under it, so apt updates those, while PHP itself changes only with a new image.',
    source: { label: 'Dockerfile', url: 'https://github.com/docker-library/php/tree/master/8.5/trixie/cli' },
    builtBy: 'Docker Official Images. The docker-library team maintains the Dockerfiles; Docker builds them.',
    channel: 'Docker Hub, tag php:8.5-cli (also 8.5.12-cli-trixie), one image for each of 8 architectures. Pull a new image to update.',
  },
  {
    id: 'docker-alpine',
    label: 'Official Docker image (Alpine)',
    variant: 'php:8.5-cli-alpine',
    distro: { type: 'apk', namespace: 'alpine' },
    install: 'docker pull php:8.5-cli-alpine',
    about: 'The same build recipe as the Debian image, on Alpine 3.24 with musl libc. {system}',
    source: { label: 'Dockerfile', url: 'https://github.com/docker-library/php/tree/master/8.5/alpine3.24/cli' },
    builtBy: 'Docker Official Images. The docker-library team maintains the Dockerfiles; Docker builds them.',
    channel: 'Docker Hub, tag php:8.5-cli-alpine (also 8.5.12-cli-alpine3.24), one image for each of 8 architectures. Pull a new image to update.',
  },
  {
    id: 'debian-13-sury',
    label: 'Debian 13 + packages.sury.org',
    variant: 'php8.5 packages',
    distro: { type: 'deb', namespace: 'debian' },
    install: '# after adding packages.sury.org, see the repository link above\napt install php8.5-{cli,curl,mbstring,xml,intl,gd,zip,mysql,pgsql,sqlite3,bcmath,readline}',
    about: 'Debian 13 itself ships PHP 8.4; this third-party repository is the common way to get 8.5 on it. {system}',
    source: { label: 'Repository', url: 'https://deb.sury.org/' },
    builtBy: "Ondřej Surý, who also maintains PHP in Debian itself. The packaging matches Debian's.",
    channel: 'packages.sury.org through apt, signed with his own key. You trust that key, not Debian.',
  },
  {
    id: 'ubuntu-26.04',
    label: 'Ubuntu 26.04',
    variant: 'php8.5 packages',
    distro: { type: 'deb', namespace: 'ubuntu' },
    install: 'apt install php8.5-{cli,curl,mbstring,xml,intl,gd,zip,mysql,pgsql,sqlite3,bcmath,readline}',
    about: 'Ubuntu 26.04 stays on PHP 8.5.4 and backports security fixes into it, so the package revision tells you more than the PHP version. {system}',
    source: { label: 'Package history', url: 'https://launchpad.net/ubuntu/+source/php8.5/{version}' },
    builtBy: "Canonical, from Debian's packaging, compiled on Launchpad.",
    channel: 'The Ubuntu archive through apt, component main, in resolute-security and resolute-updates.',
  },
  {
    id: 'alpine-3.24',
    label: 'Alpine 3.24',
    variant: 'php85 packages',
    distro: { type: 'apk', namespace: 'alpine' },
    install: "apk add php85 $(printf 'php85-%s ' curl mbstring xml dom simplexml xmlreader xmlwriter intl gd zip mysqli pdo pdo_mysql pgsql pdo_pgsql pdo_sqlite sqlite3 bcmath ctype fileinfo tokenizer session iconv openssl phar sodium)",
    about: "Alpine's php85 packages, built against musl libc. {system}",
    source: { label: 'Package page', url: 'https://pkgs.alpinelinux.org/package/v3.24/community/{apkArch}/php85' },
    builtBy: "Alpine Linux, from the php85 recipe in aports, compiled on Alpine's build servers.",
    channel: 'Alpine mirrors through apk, from the community repository.',
  },
  {
    id: 'fedora-44',
    label: 'Fedora 44',
    variant: 'php packages',
    distro: { type: 'rpm', namespace: 'fedora' },
    install: 'dnf install php-{cli,common,mbstring,xml,intl,gd,pdo,mysqlnd,pgsql,bcmath,sodium,process}',
    about: "Fedora's own php packages, updated to each PHP patch release. {system}",
    source: { label: 'Package page', url: 'https://packages.fedoraproject.org/pkgs/php/php-cli/' },
    builtBy: 'The Fedora php package maintainers, compiled on Koji, the Fedora build system.',
    channel: 'Fedora mirrors through dnf, from the updates repository.',
  },
];

const ARCHES = ['amd64', 'arm64'];
const APK_ARCH = { amd64: 'x86_64', arm64: 'aarch64' };

// Keyed by source package.
const NOTES = {
  oniguruma: 'Upstream archived on 24 April 2025',
  libonig: 'Upstream archived on 24 April 2025',
};

// Source package to upstream project name; others show the source package name.
const PROJECTS = [
  [/^openssl$/, 'OpenSSL', 'https://github.com/openssl/openssl'],
  [/^libxml2$/, 'libxml2', 'https://gitlab.gnome.org/GNOME/libxml2'],
  [/^curl$/, 'curl', 'https://github.com/curl/curl'],
  [/^icu$/, 'ICU', 'https://github.com/unicode-org/icu'],
  [/^sqlite3?$/, 'SQLite', 'https://sqlite.org/src'],
  [/^libsodium$/, 'libsodium', 'https://github.com/jedisct1/libsodium'],
  [/^libzip$/, 'libzip', 'https://github.com/nih-at/libzip'],
  [/^zlib$/, 'zlib', 'https://github.com/madler/zlib'],
  [/^zlib-ng$/, 'zlib-ng', 'https://github.com/zlib-ng/zlib-ng'],
  [/^(libgd2|gd|libgd)$/, 'libgd', 'https://github.com/libgd/libgd'],
  [/^(libonig|oniguruma)$/, 'oniguruma', 'https://github.com/kkos/oniguruma'],
  [/^argon2$/, 'Argon2', 'https://github.com/P-H-C/phc-winner-argon2'],
  [/^readline(\d+)?$/, 'readline', 'https://savannah.gnu.org/projects/readline'],
  [/^libedit$/, 'libedit', 'https://thrysoee.dk/editline/'],
  [/^libffi$/, 'libffi', 'https://github.com/libffi/libffi'],
  [/^libxslt$/, 'libxslt', 'https://gitlab.gnome.org/GNOME/libxslt'],
  [/^bzip2$/, 'bzip2', 'https://gitlab.com/bzip2/bzip2'],
  [/^capstone$/, 'Capstone', 'https://github.com/capstone-engine/capstone'],
  [/^libxcrypt$/, 'libxcrypt', 'https://github.com/besser82/libxcrypt'],
  [/^pcre2$/, 'PCRE2', 'https://github.com/PCRE2Project/pcre2'],
  [/^gnu-libiconv$/, 'GNU libiconv', 'https://savannah.gnu.org/projects/libiconv'],
  [/^(postgresql-?\d*|libpq)$/, 'libpq (PostgreSQL)', 'https://github.com/postgres/postgres'],
  [/^uriparser$/, 'uriparser', 'https://github.com/uriparser/uriparser'],
  [/^libpng(\d+)?$/, 'libpng', 'https://github.com/pnggroup/libpng'],
  [/^libavif$/, 'libavif', 'https://github.com/AOMediaCodec/libavif'],
  [/^libwebp$/, 'libwebp', 'https://chromium.googlesource.com/webm/libwebp'],
  [/^libjpeg-turbo$/, 'libjpeg-turbo', 'https://github.com/libjpeg-turbo/libjpeg-turbo'],
  [/^libx?pm$/i, 'libXpm', 'https://gitlab.freedesktop.org/xorg/lib/libxpm'],
  [/^freetype$/, 'FreeType', 'https://gitlab.freedesktop.org/freetype/freetype'],
];
const project = (source) => {
  const hit = PROJECTS.find(([re]) => re.test(source));
  return { name: hit?.[1] ?? source, url: hit?.[2] ?? null };
};

// internal: maintained in php-src; bundled: an upstream copy; patched: an upstream copy with local changes.
// swappable: configure can link a system copy instead (--with-external-pcre, -gd, -uriparser, -libcrypt).
const KIND = {
  PCRE2: { kind: 'bundled', swappable: true, url: 'https://github.com/PCRE2Project/pcre2', path: 'ext/pcre/pcre2lib' },
  timelib: { kind: 'bundled', url: 'https://github.com/derickr/timelib', path: 'ext/date/lib' },
  'Time zone database': { kind: 'bundled', url: 'https://github.com/eggert/tz', path: 'ext/date/lib/timezonedb.h' },
  Lexbor: { kind: 'patched', url: 'https://github.com/lexbor/lexbor', path: 'ext/lexbor/lexbor' },
  uriparser: { kind: 'bundled', swappable: true, url: 'https://github.com/uriparser/uriparser', path: 'ext/uri/uriparser' },
  libmagic: { kind: 'patched', url: 'https://github.com/file/file', path: 'ext/fileinfo/libmagic' },
  libmbfl: { kind: 'internal', path: 'ext/mbstring/libmbfl' },
  'libgd (fork)': { kind: 'patched', swappable: true, url: 'https://github.com/libgd/libgd', path: 'ext/gd/libgd' },
  libbcmath: { kind: 'internal', path: 'ext/bcmath/libbcmath' },
  'IR JIT framework': { kind: 'internal', url: 'https://github.com/dstogov/ir', path: 'ext/opcache/jit/ir' },
  DynASM: { kind: 'bundled', path: 'ext/opcache/jit/dynasm' },
  xxHash: { kind: 'bundled', url: 'https://github.com/Cyan4973/xxHash', path: 'ext/hash/xxhash' },
  'Keccak (SHA-3)': { kind: 'bundled', url: 'https://github.com/XKCP/XKCP', path: 'ext/hash/sha3' },
  crypt_blowfish: { kind: 'bundled', swappable: true, url: 'https://www.openwall.com/crypt/', path: 'ext/standard/crypt_blowfish.c' },
};

// Extensions compiled into the binary share its NEEDED list, so map each library to its extensions by soname.
const STATIC_USERS = [
  [/^libxml2\./, ['libxml', 'dom', 'simplexml', 'xml', 'xmlreader', 'xmlwriter', 'soap', 'xsl']],
  [/^lib(ssl|crypto)\./, ['openssl']],
  [/^libonig\./, ['mbstring']],
  [/^libargon2\./, ['standard']],
  [/^libz\./, ['zlib']],
  [/^libcurl\./, ['curl']],
  [/^libsqlite3\./, ['sqlite3', 'pdo_sqlite']],
  [/^lib(readline|edit)\./, ['readline']],
  [/^libsodium\./, ['sodium']],
  [/^libpcre2-8\./, ['pcre']],
  [/^lib(gd|png\d*|jpeg|freetype|webp|avif|Xpm)\./, ['gd']],
  [/^libicu/, ['intl']],
  [/^libzip\./, ['zip']],
  [/^libpq\./, ['pgsql', 'pdo_pgsql']],
  [/^lib(e?xslt)\./, ['xsl']],
  [/^libffi\./, ['ffi']],
  [/^libgmp\./, ['gmp']],
  [/^libiconv\./, ['iconv']],
  [/^libcrypt\./, ['standard']],
  [/^libcapstone\./, ['opcache']],
  [/^liburiparser\./, ['uri']],
];

const isRuntime = (p) => /^(glibc|musl|gcc(-\d+)?)$/.test(p?.source ?? '') || ['libc6', 'musl', 'glibc', 'libgcc-s1', 'libgcc', 'libstdc++6', 'libstdc++'].includes(p?.name);

const EXTRA_USERS = { Lexbor: ['dom', 'uri'] };

const versionOf = (s) => (s ?? '').split(' ')[0] || null;

function phpAtLeast(version, major, minor) {
  const [a, b] = version.split('.').map(Number);
  return a > major || (a === major && b >= minor);
}

// Debian and Ubuntu report version 0.system; Fedora reports the real version with "Timezone Database: system".
const systemTzdata = (info) =>
  info.date?.['"Olson" Timezone Database Version'] === '0.system' || info.date?.['Timezone Database'] === 'system';

function bundledComponents(raw) {
  const info = raw.phpinfo;
  const loaded = new Set(raw.extensions.map((e) => e.name.toLowerCase()));
  const sonames = new Set(raw.objects.flatMap((o) => o.libs.map((l) => l.soname)));
  const hasLib = (prefix) => [...sonames].some((s) => s.startsWith(prefix));
  const out = [];
  const add = (name, version, ext, note) => {
    const { path, ...kind } = KIND[name] ?? {};
    out.push({ name, version: version || null, ext, note: note ?? null, ...kind, copy: path ? `https://github.com/php/php-src/${/\.[ch]$/.test(path) ? 'blob' : 'tree'}/php-${raw.php}/${path}` : null });
  };

  if (!hasLib('libpcre2-8')) add('PCRE2', versionOf(info.pcre?.['PCRE Library Version']), 'pcre');
  add('timelib', info.date?.['timelib version'], 'date');

  const tz = info.date?.['"Olson" Timezone Database Version'];
  if (tz && !systemTzdata(info)) add('Time zone database', tz, 'date');

  if (info.lexbor?.['Lexbor version']) add('Lexbor', info.lexbor['Lexbor version'], 'lexbor');
  else if (loaded.has('dom') && phpAtLeast(raw.php, 8, 4)) add('Lexbor', null, 'dom');

  if (info.uri?.['uriparser bundled version']) add('uriparser', info.uri['uriparser bundled version'], 'uri');

  if (loaded.has('fileinfo')) {
    let v = info.fileinfo?.libmagic ?? null;
    if (v && /^\d{3}$/.test(v)) v = `${v[0]}.${v.slice(1)}`;
    add('libmagic', v, 'fileinfo', 'Carries a local PHP patch');
  }
  if (loaded.has('mbstring')) add('libmbfl', info.mbstring?.['libmbfl version'], 'mbstring');
  if (loaded.has('gd') && /bundled/.test(info.gd?.['GD Version'] ?? '')) add('libgd (fork)', null, 'gd', 'Diverged from upstream');
  if (loaded.has('bcmath')) add('libbcmath', null, 'bcmath');
  if (loaded.has('zend opcache')) {
    add(phpAtLeast(raw.php, 8, 4) ? 'IR JIT framework' : 'DynASM', null, 'opcache');
  }
  add('xxHash', null, 'hash');
  add('Keccak (SHA-3)', null, 'hash');
  add('crypt_blowfish', null, 'standard');
  return out;
}

const SWAPPABLE = ['PCRE2', 'libgd', 'uriparser', 'time zone database'];

function systemSentence(raw, bundled) {
  const has = new Set(bundled.map((b) => b.name.replace(' (fork)', '').toLowerCase()));
  const loaded = new Set(raw.extensions.map((e) => e.name.toLowerCase()));
  const relevant = SWAPPABLE.filter((n) => n !== 'libgd' || loaded.has('gd'));
  const system = relevant.filter((n) => !has.has(n.toLowerCase()));
  if (system.length === 0) return 'It uses the copies bundled in php-src.';
  const list = system.length === 1 ? system[0] : `${system.slice(0, -1).join(', ')} and ${system.at(-1)}`;
  return `It uses the system ${list} instead of the ${system.length === 1 ? 'copy' : 'copies'} bundled in php-src.`;
}

function objectLabel(raw, path) {
  if (path === raw.binary) return 'php';
  return basename(path, '.so');
}

function systemLibraries(raw) {
  const byPath = new Map();
  for (const obj of raw.objects) {
    const label = objectLabel(raw, obj.path);
    for (const lib of obj.libs) {
      const entry = byPath.get(lib.path) ?? {
        soname: lib.soname,
        path: lib.path,
        package: raw.owners[lib.path]?.name ?? null,
        version: raw.owners[lib.path]?.version ?? null,
        source: raw.owners[lib.path]?.source ?? null,
        loadedBy: [],
        direct: false,
      };
      if (!entry.loadedBy.includes(label)) entry.loadedBy.push(label);
      if (obj.needed.includes(lib.soname)) entry.direct = true;
      byPath.set(lib.path, entry);
    }
  }
  return [...byPath.values()].sort((a, b) => Number(b.direct) - Number(a.direct) || a.soname.localeCompare(b.soname));
}

function packages(libs, raw) {
  const map = new Map();
  for (const lib of libs) {
    const key = lib.package ?? `(unowned) ${lib.soname}`;
    const p = map.get(key) ?? { name: lib.package, version: lib.version, source: lib.source, libs: [], direct: false, note: NOTES[lib.source] ?? null };
    p.libs.push(lib.soname);
    p.direct ||= lib.direct;
    map.set(key, p);
  }
  if (raw.tzdata && systemTzdata(raw.phpinfo)) {
    map.set('tzdata', { name: raw.tzdata.name, version: raw.tzdata.version, source: raw.tzdata.source ?? null, libs: [], direct: true, note: 'Read by PHP instead of its bundled copy' });
  }
  return [...map.values()].sort((a, b) => Number(b.direct) - Number(a.direct) || String(a.name).localeCompare(String(b.name)));
}

// purl distro qualifier: debian-13, ubuntu-26.04, fedora-44, 3.24 (Alpine)
function distroName(build, os) {
  const v = os.match(/(\d+(?:\.\d+)?)/)?.[1] ?? 'unknown';
  return build.distro.type === 'apk' ? v : `${build.distro.namespace}-${v}`;
}

function purl(build, arch, pkg, os) {
  const { type, namespace } = build.distro;
  const a = type === 'deb' ? arch : APK_ARCH[arch];
  return `pkg:${type}/${namespace}/${pkg.name}@${encodeURIComponent(pkg.version)}?arch=${a}&distro=${distroName(build, os)}`;
}

function uuid(seed) {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function cyclonedx(build, arch, data) {
  const rootRef = 'php';
  const components = [];
  const deps = new Map([[rootRef, new Set()]]);

  for (const b of data.bundled) {
    const ref = `bundled:${b.name}`;
    components.push({
      type: 'library',
      'bom-ref': ref,
      name: b.name,
      ...(b.version && { version: b.version }),
      purl: `pkg:generic/${encodeURIComponent(b.name.toLowerCase().replace(/\s+/g, '-'))}${b.version ? '@' + encodeURIComponent(b.version) : ''}`,
      properties: [
        { name: 'php:bundled-in', value: 'php-src' },
        { name: 'php:extension', value: b.ext },
      ],
    });
    deps.get(rootRef).add(ref);
  }

  for (const p of data.packages) {
    if (!p.name) continue;
    const ref = purl(build, arch, p, data.os);
    components.push({
      type: 'library',
      'bom-ref': ref,
      name: p.name,
      version: p.version,
      purl: ref,
      properties: [
        ...(p.source ? [{ name: 'php:source-package', value: p.source }] : []),
        ...p.libs.map((s) => ({ name: 'php:soname', value: s })),
        { name: 'php:direct', value: String(p.direct) },
      ],
    });
  }

  const pkgRef = new Map(data.packages.filter((p) => p.name).map((p) => [p.name, purl(build, arch, p, data.os)]));
  for (const ext of data.extensions.filter((e) => e.shared)) {
    const ref = `extension:${ext.name}`;
    components.push({ type: 'library', 'bom-ref': ref, name: `php-ext-${ext.name}`, version: data.php, properties: [{ name: 'php:file', value: ext.file }] });
    deps.get(rootRef).add(ref);
    deps.set(ref, new Set());
  }
  for (const lib of data.libraries) {
    if (!lib.direct || !lib.package) continue;
    for (const by of lib.loadedBy) {
      const ref = by === 'php' ? rootRef : `extension:${data.extensions.find((e) => e.file && basename(e.file, '.so') === by)?.name ?? by}`;
      if (deps.has(ref)) deps.get(ref).add(pkgRef.get(lib.package));
    }
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${uuid(`${build.id}-${arch}-${data.php}`)}`,
    version: 1,
    metadata: {
      timestamp: `${COLLECTED}T00:00:00Z`,
      tools: { components: [{ type: 'application', name: 'php-sbom', publisher: 'Jorg Sowa' }] },
      component: { type: 'application', 'bom-ref': rootRef, name: 'php', version: data.php, description: `${build.label} (${build.variant}), ${data.os}, ${arch}` },
    },
    components,
    dependencies: [...deps].map(([ref, set]) => ({ ref, dependsOn: [...set].filter(Boolean) })),
  };
}

function graph(raw, data) {
  const loaded = new Map(raw.extensions.map((e) => [e.name.toLowerCase().replace('zend opcache', 'opcache'), e.name]));
  const pkgOf = new Map(data.libraries.map((l) => [l.path, l.package ?? `?${l.soname}`]));
  const pathOf = new Map(data.libraries.map((l) => [l.soname, l.path]));
  const nodes = new Map();
  const edges = new Set();
  const node = (id, n) => nodes.get(id) ?? (nodes.set(id, { id, ...n }), nodes.get(id));
  const shared = new Set(data.extensions.filter((e) => e.shared).map((e) => e.name));
  const ext = (name) => node(`ext:${name}`, { label: loaded.get(name) ?? name, kind: 'extension', shared: shared.has(loaded.get(name)) });
  for (const name of loaded.keys()) ext(name);
  const edge = (a, b) => a !== b && edges.add(`${a}>${b}`);

  for (const b of data.bundled) {
    const id = `bundled:${b.name}`;
    node(id, { label: b.name, kind: b.kind, swappable: Boolean(b.swappable), version: b.version, note: b.note, url: b.url ?? null, copy: b.copy });
    for (const user of [b.ext, ...(EXTRA_USERS[b.name] ?? [])]) {
      if (loaded.has(user)) edge(ext(user).id, id);
    }
  }

  // One box per upstream project: Alpine splits OpenSSL into libssl3 and libcrypto3, for example.
  const pkgNode = (name) => {
    const p = data.packages.find((x) => (x.name ?? `?${x.libs[0]}`) === name);
    const source = p?.source ?? p?.name ?? name.slice(1);
    const n = node(`os:${source}`, {
      label: project(source).name,
      url: project(source).url,
      source,
      kind: isRuntime(p) ? 'runtime' : 'external',
      version: p?.version ?? null,
      note: p?.note ?? null,
      packages: [],
      libs: [],
    });
    if (p && !n.packages.some((x) => x.name === p.name)) {
      n.packages.push({ name: p.name, version: p.version });
      n.libs.push(...p.libs);
    }
    return n;
  };

  for (const obj of raw.objects) {
    const isBinary = obj.path === raw.binary;
    const owner = isBinary ? null : () => ext(objectLabel(raw, obj.path).toLowerCase());
    for (const soname of obj.needed) {
      const path = pathOf.get(soname);
      if (!path) continue;
      const pkg = pkgNode(pkgOf.get(path));
      if (pkg.kind === 'runtime') continue;
      const users = isBinary ? (STATIC_USERS.find(([re]) => re.test(soname))?.[1] ?? []).filter((u) => loaded.has(u)) : [];
      if (owner) edge(owner().id, pkg.id);
      else if (users.length) users.forEach((u) => edge(ext(u).id, pkg.id));
      else edge(node('php-binary', { label: 'php binary', kind: 'extension', core: true }).id, pkg.id);
    }
  }

  const runtime = data.packages.filter(isRuntime).map((p) => ({ name: p.name, version: p.version }));
  for (const id of [...nodes.keys()].filter((id) => nodes.get(id).kind === 'runtime')) nodes.delete(id);
  return {
    nodes: [...nodes.values()],
    edges: [...edges].map((e) => e.split('>')).filter(([a, b]) => nodes.has(a) && nodes.has(b)),
    runtime,
  };
}

const [PRIMARY, OTHER] = ARCHES;
const out = { collected: COLLECTED, builds: BUILDS.map(({ distro, source, about, ...b }) => b), arch: PRIMARY, otherArch: OTHER, sboms: {} };
mkdirSync(join(root, 'public/sbom'), { recursive: true });

const readRaw = (build, arch) => {
  const file = join(rawDir, `${build.id}-${arch}.json`);
  if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf8'));
  console.warn(`missing ${file}`);
  return null;
};
const onlyIn = (a, b) => a.filter((p) => !b.some((q) => q.name === p.name && q.version === p.version)).map((p) => p.name);

for (const build of BUILDS) {
  const raw = readRaw(build, PRIMARY);
  if (!raw) continue;
  const libraries = systemLibraries(raw);
  const data = {
    php: raw.php,
    os: raw.os,
    arch: PRIMARY,
    binaryPackage: raw.binaryOwner,
    extensions: raw.extensions
      .map((e) => ({ name: e.name, shared: Boolean(e.file), file: e.file }))
      .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' })),
    bundled: bundledComponents(raw),
    libraries,
    packages: packages(libraries, raw),
  };
  data.graph = graph(raw, data);
  data.about = build.about.replace('{system}', systemSentence(raw, data.bundled));
  data.source = {
    label: build.source.label,
    url: build.source.url.replace('{apkArch}', APK_ARCH[PRIMARY]).replace('{version}', raw.binaryOwner?.version ?? ''),
  };
  data.changelog = `https://www.php.net/ChangeLog-8.php#${raw.php}`;
  const other = readRaw(build, OTHER);
  if (other) {
    const otherPackages = packages(systemLibraries(other), other);
    data.archDiff = { onlyPrimary: onlyIn(data.packages, otherPackages), onlyOther: onlyIn(otherPackages, data.packages) };
  }
  const cdxPath = `/sbom/${build.id}.cdx.json`;
  writeFileSync(join(root, 'public', cdxPath), JSON.stringify(cyclonedx(build, PRIMARY, data), null, 2) + '\n');
  out.sboms[build.id] = { ...data, cyclonedx: cdxPath };
  console.log(`${build.id}: php ${data.php}, ${data.bundled.length} bundled, ${data.packages.length} packages, ${libraries.length} libraries`);
}

writeFileSync(join(root, 'src/data/php-sbom.json'), JSON.stringify(out, null, 2) + '\n');
