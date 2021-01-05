package winrmhelper

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/masterzen/winrm"
)

//WinRMResult holds the stdout, stderr and exit code of a powershell command
type WinRMResult struct {
	Stdout   string
	StdErr   string
	ExitCode int
}

// RunWinRMCommand will run a powershell command and return the stdout and stderr
// The output is converted to JSON if the json patameter is set to true.
func RunWinRMCommand(conn *winrm.Client, cmds []string, json bool, forceArray bool) (*WinRMResult, error) {
	if json {
		cmds = append(cmds, "| ConvertTo-Json")
	}

	cmd := strings.Join(cmds, " ")
	encodedCmd := winrm.Powershell(cmd)
	log.Printf("[DEBUG] Running command %s via powershell", cmd)
	log.Printf("[DEBUG] Encoded command: %s", encodedCmd)
	stdout, stderr, res, err := conn.RunWithString(encodedCmd, "")
	log.Printf("[DEBUG] Powershell command exited with code %d", res)
	if res != 0 {
		log.Printf("[DEBUG] Stdout: %s, Stderr: %s", stdout, stderr)
	}
	if err != nil {
		log.Printf("[DEBUG] run error : %s", err)
		return nil, fmt.Errorf("powershell command failed with exit code %d\nstdout: %s\nstderr: %s\nerror: %s", res, stdout, stderr, err)
	}

	result := &WinRMResult{
		Stdout:   strings.TrimSpace(stdout),
		StdErr:   stderr,
		ExitCode: res,
	}

	if json && forceArray && result.Stdout != "" && string(result.Stdout[0]) != "[" {
		result.Stdout = fmt.Sprintf("[%s]", result.Stdout)
	}

	return result, nil
}

// SanitiseTFInput returns the value of a resource field after some basic sanitisation checks
// to protect ourselves from command injection
func SanitiseTFInput(d *schema.ResourceData, key string) string {
	cleanupReplacer := strings.NewReplacer(
		"`", "``",
		`"`, "`\"",
		"$", "`$",
		"\x00", "`0",
		"\x07", "`a",
		"\x08", "`b",
		"\x1f", "`e",
		"\x0c", "`f",
		"\n", "`n",
		"\r", "`r",
		"\t", "`t",
		"\v", "`v",
	)

	out := cleanupReplacer.Replace(d.Get(key).(string))
	log.Printf("[DEBUG] sanitising key %q to: %s", key, out)
	return out
}

// SetMachineExtensionName will add the necessary GUIDs to the GPO's gPCMachineExtensionNames attribute.
// These are required for the security settings part of a GPO to work.
func SetMachineExtensionNames(client *winrm.Client, gpoDN, value string) error {
	cmd := fmt.Sprintf(`Set-ADObject -Identity "%s" -Replace @{gPCMachineExtensionNames="%s"}`, gpoDN, value)
	result, err := RunWinRMCommand(client, []string{cmd}, false, false)
	if err != nil {
		return fmt.Errorf("error while setting machine extension names for GPO %q: %s", gpoDN, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("command to set machine extension names for GPO %q failed, stderr: %s, stdout: %s", gpoDN, result.StdErr, result.Stdout)
	}
	return nil
}

// SliceInterfacesToStrings converts an interface slice to a string slice. The
// function does not attempt to do any sanity checking and will panic if one of
// the items in the slice is not a string.
func SliceInterfacesToStrings(s []interface{}) []string {
	var d []string
	for _, v := range s {
		if o, ok := v.(string); ok {
			d = append(d, o)
		}
	}
	return d
}

// AD replication
const pscmdsyncaddomain = `
function Sync-DomainController {
    [CmdletBinding()]
    param(
        [string] $Domain = $Env:USERDNSDOMAIN
    )
    $DistinguishedName = (Get-ADDomain -Server $Domain).DistinguishedName
    (Get-ADDomainController -Filter * -Server $Domain).Name | ForEach-Object {
        Write-Verbose -Message "Sync-DomainController - Forcing synchronization $_"
        repadmin /syncall $_ $DistinguishedName /e /A | Out-Null
    }
}
`
const pscmdmetadata = `
function Get-WinADForestReplicationPartnerMetaData {
    [CmdletBinding()]
    param(
        [switch] $Extended
    )
    $Replication = Get-ADReplicationPartnerMetadata -Target * -Partition * -ErrorAction SilentlyContinue -ErrorVariable ProcessErrors
    if ($ProcessErrors) {
        foreach ($_ in $ProcessErrors) {
            Write-Warning -Message "Get-WinADForestReplicationPartnerMetaData - Error on server $($_.Exception.ServerName): $($_.Exception.Message)"
        }
    }
    foreach ($_ in $Replication) {
        $ServerPartner = (Resolve-DnsName -Name $_.PartnerAddress -Verbose:$false -ErrorAction SilentlyContinue)
        $ServerInitiating = (Resolve-DnsName -Name $_.Server -Verbose:$false -ErrorAction SilentlyContinue)
        $ReplicationObject = [ordered] @{
            LastReplicationAttempt         = $_.LastReplicationAttempt
            LastReplicationResult          = $_.LastReplicationResult
            LastReplicationSuccess         = $_.LastReplicationSuccess
        }
        if ($Extended) {
            $ReplicationObject.Partner = $_.Partner
            $ReplicationObject.PartnerAddress = $_.PartnerAddress
            $ReplicationObject.PartnerGuid = $_.PartnerGuid
            $ReplicationObject.PartnerInvocationId = $_.PartnerInvocationId
            $ReplicationObject.PartitionGuid = $_.PartitionGuid
        }
        [PSCustomObject] $ReplicationObject
    }
}
`
const pscmdstartsync = `
function Start-ADSync {
    $now = Get-Date
    $sync = $false

    do
    {
       # Force sync
       Sync-DomainController

       # Ensure replication is applied on all AD
       $results = Get-WinADForestReplicationPartnerMetaData
       
       foreach ($result in $results) {
        if ($result.LastReplicationSuccess -gt $now) {
            $sync = $true
        }
        else {
            $sync = $false
        }
       }
    }
    until ($sync)
    return "Sync finished on all DC's"
}
`

// ImportRepCmdlet starts replication on all domain controllers
func ImportRepCmdlet(client *winrm.Client) error {
	var cmd string
	// cmdlet Sync-DomainController
	cmd = fmt.Sprintf(pscmdsyncaddomain)
	result, err := RunWinRMCommand(client, []string{cmd}, false, false)

	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command import ADSync exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	// cmdlet Get-WinADForestReplicationPartnerMetaData
	cmd = fmt.Sprintf(pscmdmetadata)
	result, err = RunWinRMCommand(client, []string{cmd}, false, false)

	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command import ADSync exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	// cmdlet Start-ADSync
	cmd = fmt.Sprintf(pscmdstartsync)
	result, err = RunWinRMCommand(client, []string{cmd}, false, false)

	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command import ADSync exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	return nil
}

// GetRepCmdlet check if replication cmdlet are available
func GetRepCmdlet(client *winrm.Client) error {
	cmd := fmt.Sprintf("Get-Command Start-ADSync")
	result, err := RunWinRMCommand(client, []string{cmd}, false, false)

	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command 'Get-Command Start-ADSync' exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	return nil
}

// StartADSync check if replication cmdlet are available
func StartADSync(client *winrm.Client) error {
	cmd := fmt.Sprintf("Start-ADSync")
	result, err := RunWinRMCommand(client, []string{cmd}, false, false)

	if err != nil {
		return err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command Start-ADSync exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	return nil
}
