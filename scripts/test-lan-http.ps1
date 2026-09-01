$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputDirectory = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'build\lan-http-test'))
$requiredPrefix = $projectRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $outputDirectory.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean output outside project: $outputDirectory"
}

if (Test-Path -LiteralPath $outputDirectory) {
    Remove-Item -LiteralPath $outputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDirectory | Out-Null

function Resolve-JavaTool([string] $toolName) {
    if ($env:JAVA_HOME) {
        $candidate = Join-Path $env:JAVA_HOME "bin\$toolName.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $command = Get-Command "$toolName.exe" -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $fallback = "C:\Program Files\Java\jdk-1.8\bin\$toolName.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    throw "$toolName was not found through JAVA_HOME, PATH, or the local JDK 8 fallback"
}

$javac = Resolve-JavaTool 'javac'
$java = Resolve-JavaTool 'java'
$nanoHttpdJar = if ($env:NANOHTTPD_JAR) {
    [System.IO.Path]::GetFullPath($env:NANOHTTPD_JAR)
} else {
    Join-Path $projectRoot 'build\deps\nanohttpd-2.3.1.jar'
}
$expectedNanoHttpdHash = 'DE864C47818157141A24C9ACB36DF0C47D7BF15B7FF48C90610F3EB4E5DF0E58'
if (-not (Test-Path -LiteralPath $nanoHttpdJar)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $nanoHttpdJar) | Out-Null
    Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://repo1.maven.org/maven2/org/nanohttpd/nanohttpd/2.3.1/nanohttpd-2.3.1.jar' `
        -OutFile $nanoHttpdJar
}
$actualNanoHttpdHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $nanoHttpdJar).Hash.ToUpperInvariant()
if ($actualNanoHttpdHash -ne $expectedNanoHttpdHash) {
    throw "NanoHTTPD 2.3.1 SHA-256 mismatch: $actualNanoHttpdHash"
}

$productionSources = @(
    'LanAddressGuard.java',
    'LanHttpServer.java',
    'LanJson.java',
    'LanWireCodec.java',
    'LanApiDispatcher.java',
    'LanServiceHealthPolicy.java',
    'LanNetworkGuard.java',
    'LanServerOwner.java'
) | ForEach-Object { Join-Path $projectRoot "app\src\main\java\com\passwordvault\local\lan\$_" }
$coreSources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'app\src\main\java\com\passwordvault\local\core') -Filter '*.java' -Recurse -File
$testSources = @(
    'LanHttpServerTest.java',
    'LanLifecycleTest.java'
    'LanApiDispatcherTest.java'
) | ForEach-Object { Join-Path $projectRoot "app\src\test\java\com\passwordvault\local\lan\$_" }

& $javac -encoding UTF-8 -source 8 -target 8 -cp $nanoHttpdJar -d $outputDirectory `
    @($coreSources.FullName) @productionSources @testSources
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$testClasses = @(
    'com.passwordvault.local.lan.LanHttpServerTest',
    'com.passwordvault.local.lan.LanLifecycleTest'
    'com.passwordvault.local.lan.LanApiDispatcherTest'
)
foreach ($testClass in $testClasses) {
    & $java -ea -cp "$outputDirectory;$nanoHttpdJar" $testClass
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
exit 0
