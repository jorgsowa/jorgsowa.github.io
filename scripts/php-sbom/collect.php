<?php
// Runs inside a container; prints what this PHP build bundles and loads, as JSON.

function sh(string $cmd): string
{
    return trim((string) shell_exec($cmd . ' 2>/dev/null'));
}

function phpinfoSections(): array
{
    ob_start();
    phpinfo();
    $sections = [];
    $current = 'General';
    foreach (explode("\n", ob_get_clean()) as $line) {
        $line = rtrim($line);
        if (preg_match('/^(.+?) => (.*?)(?: => .*)?$/', $line, $m)) {
            $sections[$current][trim($m[1])] ??= trim($m[2]);
        } elseif ($line !== '' && !str_contains($line, ' ') || preg_match('/^Zend OPcache$/', $line)) {
            $current = $line;
        }
    }
    return $sections;
}

function apkOrigin(string $pkg): ?string
{
    // The installed database lists each package as P:<name> followed by its fields, o:<origin> among them.
    foreach (explode("\n\n", (string) @file_get_contents('/lib/apk/db/installed')) as $block) {
        if (preg_match('/^P:' . preg_quote($pkg, '/') . '$/m', $block) && preg_match('/^o:(.+)$/m', $block, $m)) {
            return $m[1];
        }
    }
    return null;
}

function owner(string $path, string $pm): ?array
{
    $candidates = array_unique([$path, realpath($path) ?: $path]);
    // usrmerge: dpkg may record /lib/... while ldd reports /usr/lib/... or the reverse
    foreach ($candidates as $p) {
        $candidates[] = str_starts_with($p, '/usr/') ? substr($p, 4) : '/usr' . $p;
    }
    foreach (array_unique($candidates) as $p) {
        if ($pm === 'dpkg') {
            $out = sh('dpkg -S ' . escapeshellarg($p));
            if ($out !== '' && !str_starts_with($out, 'diversion')) {
                $pkg = trim(explode(':', explode("\n", $out)[0])[0]);
                $pkg = explode(',', $pkg)[0];
                [$version, $source] = explode("\t", sh('dpkg-query -W -f=\'${Version}\t${source:Package}\' ' . escapeshellarg($pkg))) + [1 => null];
                return ['name' => $pkg, 'version' => $version, 'source' => $source];
            }
        } elseif ($pm === 'rpm') {
            $out = sh('rpm -qf --qf \'%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n\' ' . escapeshellarg($p));
            if (preg_match('/^(\S+)\t(\S+)\t(\S+)$/m', $out, $m)) {
                return ['name' => $m[1], 'version' => $m[2], 'source' => preg_replace('/-[^-]+-[^-]+\.src\.rpm$/', '', $m[3])];
            }
        } elseif ($pm === 'apk') {
            $out = sh('apk info --who-owns ' . escapeshellarg($p));
            if (preg_match('/is owned by (.+)$/', $out, $m) && preg_match('/^(.+)-([^-]+-r\d+)$/', trim($m[1]), $v)) {
                return ['name' => $v[1], 'version' => $v[2], 'source' => apkOrigin($v[1])];
            }
        }
    }
    return null;
}

function elfObject(string $path): array
{
    preg_match_all('/\(NEEDED\).*\[(.+)\]/', sh('readelf -d ' . escapeshellarg($path)), $needed);
    $libs = [];
    foreach (explode("\n", sh('ldd ' . escapeshellarg($path))) as $line) {
        if (preg_match('/^\s*(\S+) => (\/\S+)/', $line, $m)) {
            $libs[] = ['soname' => $m[1], 'path' => $m[2]];
        }
    }
    return ['path' => $path, 'needed' => $needed[1], 'libs' => $libs];
}

$pm = match (true) {
    is_executable('/usr/bin/dpkg') => 'dpkg',
    is_executable('/sbin/apk') || is_executable('/usr/bin/apk') => 'apk',
    is_executable('/usr/bin/rpm') => 'rpm',
    default => null,
};
$extDir = ini_get('extension_dir');
$binary = realpath(PHP_BINARY);

$loaded = array_merge(get_loaded_extensions(), get_loaded_extensions(true));
$files = [];
foreach (glob($extDir . '/*.so') ?: [] as $file) {
    $files[strtolower(basename($file, '.so'))] = $file;
}
$extensions = [];
foreach (array_unique($loaded) as $name) {
    $key = strtolower($name === 'Zend OPcache' ? 'opcache' : $name);
    $extensions[] = ['name' => $name, 'file' => $files[$key] ?? null];
}

$objects = [elfObject($binary)];
foreach ($extensions as $ext) {
    if ($ext['file']) {
        $objects[] = elfObject($ext['file']);
    }
}

$owners = [];
foreach ($objects as $obj) {
    foreach ($obj['libs'] as $lib) {
        $owners[$lib['path']] ??= owner($lib['path'], $pm);
    }
}

$tzdata = null;
if ($pm !== null) {
    $tzdata = owner('/usr/share/zoneinfo/UTC', $pm);
}

preg_match('/^PRETTY_NAME="?(.*?)"?$/m', (string) @file_get_contents('/etc/os-release'), $os);

echo json_encode([
    'php' => PHP_VERSION,
    'os' => $os[1] ?? 'unknown',
    'arch' => php_uname('m'),
    'packageManager' => $pm,
    'binary' => $binary,
    'binaryOwner' => $pm ? owner($binary, $pm) : null,
    'extensionDir' => $extDir,
    'extensions' => $extensions,
    'objects' => $objects,
    'owners' => $owners,
    'tzdata' => $tzdata,
    'phpinfo' => phpinfoSections(),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
