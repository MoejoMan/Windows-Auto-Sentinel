# WinAutoSentinel GUI Script
# Contains all Windows Forms GUI logic for pre-scan options and launching the main scan

Add-Type -AssemblyName System.Windows.Forms

function Show-PreScanOptions {
    param(
        [bool]$IsAdmin
    )
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WinAutoSentinel Pre-Scan Options"
    $form.Size = New-Object System.Drawing.Size(420, 420)
    $form.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Select scan categories to include:"
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $form.Controls.Add($label)

    $categories = @(
        @{Name="Scheduled Tasks"; Var="scheduledTasks"; Admin=$false},
        @{Name="Registry Run Keys"; Var="registryRunKeys"; Admin=$false},
        @{Name="Startup Folders"; Var="startupFolders"; Admin=$false},
        @{Name="USB Device History"; Var="usbHistory"; Admin=$false},
        @{Name="Browser Extensions"; Var="browserExtensions"; Admin=$false},
        @{Name="PowerShell History"; Var="psHistory"; Admin=$false},
        @{Name="Prefetch Files (Admin)"; Var="prefetchFiles"; Admin=$true},
        @{Name="Unusual Services"; Var="unusualServices"; Admin=$false},
        @{Name="Event Log Entries (Admin)"; Var="eventLogEntries"; Admin=$true},
        @{Name="Hosts File Entries"; Var="hostsFileEntries"; Admin=$false},
        @{Name="Firewall Rules"; Var="firewallRules"; Admin=$false}
    )

    $checkboxes = @{}
    $y = 40
    foreach ($cat in $categories) {
        $cb = New-Object System.Windows.Forms.CheckBox
        $cb.Text = $cat.Name + ($(if ($cat.Admin -and -not $IsAdmin) { ' (Requires Admin)' } else { '' }))
        $cb.Checked = $true
        $cb.Location = New-Object System.Drawing.Point(20, $y)
        $cb.Width = 350
        $form.Controls.Add($cb)
        $checkboxes[$cat.Var] = $cb
        $y += 28
    }


    $adminBtn = New-Object System.Windows.Forms.Button
    $adminBtn.Text = "Relaunch as Admin"
    $adminBtn.Location = New-Object System.Drawing.Point(20, ($y + 10))
    $adminBtn.Size = New-Object System.Drawing.Size(140, 32)
    $adminBtn.Add_Click({
        $psExe = (Get-Command powershell.exe).Source
        $scriptPath = $MyInvocation.MyCommand.Definition
        Start-Process -FilePath $psExe -ArgumentList "-NoExit", "-ExecutionPolicy Bypass", "-File", "$scriptPath" -Verb RunAs
        $form.Close()
        exit
    })
    if ($IsAdmin) { $adminBtn.Enabled = $false }
    $form.Controls.Add($adminBtn)

    $launchBtn = New-Object System.Windows.Forms.Button
    $launchBtn.Text = "Launch Scan"
    $launchBtn.Location = New-Object System.Drawing.Point(200, ($y + 10))
    $launchBtn.Size = New-Object System.Drawing.Size(140, 32)
    $launchBtn.Add_Click({
        $form.Tag = @{}
        foreach ($cat in $categories) {
            $form.Tag[$cat.Var] = $checkboxes[$cat.Var].Checked
        }
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($launchBtn)

    $form.ShowDialog() | Out-Null
    return $form.Tag
}
