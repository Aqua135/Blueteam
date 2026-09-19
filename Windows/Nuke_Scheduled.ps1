<#
.SYNOPSIS
    Removes all Scheduled Tasks on a Windows host (the Windows equivalent of cron).
.DESCRIPTION
    Blue-team cleanup script — unregisters every scheduled task except the built-in
    Microsoft\Windows tasks needed for OS stability, since deleting those can break
    Windows Update, defrag, telemetry cleanup, etc. Pass -IncludeMicrosoftTasks to
    nuke everything, including OS-managed tasks (aggressive; may break the box).
.PARAMETER IncludeMicrosoftTasks
    If set, also removes tasks under \Microsoft\Windows\... Off by default.
.PARAMETER DryRun
    If set, only lists what would be removed.
.EXAMPLE
    .\Nuke-ScheduledTasks.ps1
    .\Nuke-ScheduledTasks.ps1 -IncludeMicrosoftTasks -DryRun
#>

[CmdletBinding()]
param(
    [switch]$IncludeMicrosoftTasks,
    [switch]$DryRun
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$tasks = Get-ScheduledTask

if (-not $IncludeMicrosoftTasks) {
    $tasks = $tasks | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" }
}

Write-Host "=== Found $($tasks.Count) scheduled task(s) to remove ===" -ForegroundColor Cyan

foreach ($task in $tasks) {
    $full = Join-Path $task.TaskPath $task.TaskName
    if ($DryRun) {
        Write-Host "[dry-run] Would remove: $full"
    } else {
        try {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-Host "Removed: $full" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove ${full}: $_"
        }
    }
}

Write-Host "Done. Also consider checking:" -ForegroundColor Yellow
Write-Host "  - Task Scheduler task .xml/.job leftovers in C:\Windows\System32\Tasks"
Write-Host "  - WMI event subscriptions (Get-WmiObject -Namespace root\subscription -Class __EventFilter)"
Write-Host "  - Startup folder items and Run/RunOnce registry keys (separate persistence vectors)"
