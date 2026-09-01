$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputDirectory = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'build\core-test'))
$requiredPrefix = $projectRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $outputDirectory.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean output outside project: $outputDirectory"
}

if (Test-Path -LiteralPath $outputDirectory) {
    Remove-Item -LiteralPath $outputDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDirectory | Out-Null

$javac = 'C:\Program Files\Java\jdk-1.8\bin\javac.exe'
$java = 'C:\Program Files\Java\jdk-1.8\bin\java.exe'
if (-not (Test-Path -LiteralPath $javac) -or -not (Test-Path -LiteralPath $java)) {
    throw 'JDK 8 was not found at C:\Program Files\Java\jdk-1.8\bin'
}

$productionSources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'app\src\main\java\com\passwordvault\local\core') -Filter '*.java' -Recurse -File
$uiSourceDirectory = Join-Path $projectRoot 'app\src\main\java\com\passwordvault\local\ui'
$uiSources = if (Test-Path -LiteralPath $uiSourceDirectory) {
    Get-ChildItem -LiteralPath $uiSourceDirectory -Filter '*Controller.java' -File
} else {
    @()
}
$testSources = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'app\src\test\java\com\passwordvault\local\core') -Filter '*.java' -Recurse -File
$sourcePaths = @($productionSources.FullName) + @($uiSources.FullName) + @($testSources.FullName)

& $javac -encoding UTF-8 -source 8 -target 8 -d $outputDirectory $sourcePaths
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$projectRootProperty = "-Dpasswordvault.projectRoot=$projectRoot"
& $java $projectRootProperty -ea -cp $outputDirectory com.passwordvault.local.core.CoreTestMain
exit $LASTEXITCODE
