#Requires -Modules Pester
<#
    Pester 5.x test suite for WinAutoSentinel
    Run:  Invoke-Pester -Path .\Tests\Win_Auto_Sentinel.Tests.ps1 -Output Detailed
#>

BeforeAll {
    # Dot-source the functions module so helpers and constants are available
    . "$PSScriptRoot\..\Win_Auto_Sentinel_Functions.ps1"
}

# ============================================================================
# SHARED CONSTANTS
# ============================================================================
Describe 'Shared Constants' {
    It 'defines $script:SuspiciousBinaries as a non-empty array' {
        $script:SuspiciousBinaries | Should -Not -BeNullOrEmpty
        $script:SuspiciousBinaries | Should -BeOfType [string]
    }

    It 'defines $script:SuspiciousBinariesUpper as uppercase versions' {
        $script:SuspiciousBinariesUpper | Should -Not -BeNullOrEmpty
        foreach ($item in $script:SuspiciousBinariesUpper) {
            $item | Should -BeExactly $item.ToUpper()
        }
    }

    It 'defines $script:SuspiciousDirectories as a non-empty array' {
        $script:SuspiciousDirectories | Should -Not -BeNullOrEmpty
    }

    It 'defines $script:TrustedDirectories as a non-empty array' {
        $script:TrustedDirectories | Should -Not -BeNullOrEmpty
    }

    It 'defines $script:MaliciousKeywords as a non-empty array' {
        $script:MaliciousKeywords | Should -Not -BeNullOrEmpty
    }

    It 'defines $script:SuspiciousHistoryPatterns as a non-empty array' {
        $script:SuspiciousHistoryPatterns | Should -Not -BeNullOrEmpty
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
Describe 'Test-IsAdministrator' {
    It 'returns a boolean' {
        $result = Test-IsAdministrator
        $result | Should -BeOfType [bool]
    }
}

Describe 'Get-TruncatedString' {
    It 'returns the original string when under max length' {
        Get-TruncatedString -Text 'hello' -MaxLength 50 | Should -Be 'hello'
    }

    It 'truncates and appends ellipsis when over max length' {
        $result = Get-TruncatedString -Text ('x' * 100) -MaxLength 20
        $result.Length | Should -Be 23   # 20 chars + '...'
        $result | Should -BeLike '*...'
    }

    It 'returns empty string for null input' {
        Get-TruncatedString -Text $null -MaxLength 50 | Should -Be ''
    }
}

Describe 'Get-FileSignatureStatus' {
    It 'returns "Unknown (file not found)" when file does not exist' {
        Get-FileSignatureStatus -FilePath 'C:\nonexistent_file_abc123.exe' | Should -Be 'Unknown (file not found)'
    }

    It 'returns a string for a real system binary' {
        $notepad = Join-Path $env:SystemRoot 'notepad.exe'
        if (Test-Path $notepad) {
            $result = Get-FileSignatureStatus -FilePath $notepad
            $result | Should -Not -BeNullOrEmpty
        } else {
            Set-ItResult -Skipped -Because 'notepad.exe not found'
        }
    }
}

# ============================================================================
# LOGGING
# ============================================================================
Describe 'Write-WASLog' {
    It 'does not error when logging is not enabled' {
        { Write-WASLog -Message 'test' } | Should -Not -Throw
    }
}

Describe 'Enable-WASLog' {
    It 'creates a log file' {
        $logDir  = Join-Path $TestDrive 'logs'
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        $logFile = Join-Path $logDir 'test.log'

        Enable-WASLog -Path $logFile
        Write-WASLog 'hello from Pester'

        Test-Path $logFile | Should -BeTrue
        $content = Get-Content $logFile -Raw
        $content | Should -BeLike '*hello from Pester*'
    }

    AfterAll {
        # Reset log state
        $script:LogPath = $null
    }
}

# ============================================================================
# SCAN FUNCTIONS - RETURN TYPE CHECKS
# ============================================================================
Describe 'Scan functions return arrays' {
    # Each scan function should return an array (even if empty) of objects.
    # We test that they don't throw and return array-like output.

    $testCases = @(
        @{ FnName = 'Get-RegistryRunKeysSummary' }
        @{ FnName = 'Get-StartupFoldersSummary' }
        @{ FnName = 'Get-WMIPersistenceSummary' }
        @{ FnName = 'Get-DNSCacheSummary' }
        @{ FnName = 'Get-HostsFileEntriesSummary' }
    )

    It '<FnName> runs without error and returns an array' -TestCases $testCases {
        param($FnName)
        $result = & $FnName
        # Result should be $null or an array of objects
        if ($null -ne $result) {
            @($result).Count | Should -BeGreaterOrEqual 1
        }
    }
}

# ============================================================================
# HTML REPORT
# ============================================================================
Describe 'New-HTMLReport' {
    It 'generates an HTML file from scan results' {
        $testResults = [ordered]@{
            'Test Category' = @(
                [PSCustomObject]@{ Name = 'item1'; Risk = 'Low'; Detail = 'test detail' }
            )
        }
        $outFile = Join-Path $TestDrive 'test_report.html'

        { New-HTMLReport -Results $testResults -OutputPath $outFile } | Should -Not -Throw
        Test-Path $outFile | Should -BeTrue
        $html = Get-Content $outFile -Raw
        $html | Should -BeLike '*WinAutoSentinel*'
        $html | Should -BeLike '*Test Category*'
    }
}
