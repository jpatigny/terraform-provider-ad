package winpshelper

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/masterzen/winrm"
)

//WinRMResult holds the stdout, stderr and exit code of a powershell command
type WinRMResult struct {
	Stdout   string
	StdErr   string
	ExitCode int
}

// PowerShell struct
type PowerShell struct {
	powerShell string
}

// New create new session
func New() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

// execute is executing powershell cmds
func (p *PowerShell) execute(args ...string) (stdOut string, stdErr string, Res int, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	var exerr *exec.ExitError
	var res int = 0
	if errors.As(err, &exerr) {
		res = exerr.ExitCode()
	}
	stdOut, stdErr, Res = stdout.String(), stderr.String(), res
	return
}

// RunWinRMCommandLocal will run a powershell command and return the stdout and stderr
// The output is converted to JSON if the json patameter is set to true.
func RunWinRMCommandLocal(cmds []string, json bool, forceArray bool) (*WinRMResult, error) {
	if json {
		cmds = append(cmds, "| convertto-json")
	}

	cmd := strings.Join(cmds, " ")
	encodedCmd := winrm.Powershell(cmd)
	fmt.Printf("[DEBUG] Running command %s via powershell", cmd)
	fmt.Printf("[DEBUG] Encoded command: %s", encodedCmd)
	posh := New()
	stdout, stderr, res, err := posh.execute(encodedCmd)
	fmt.Printf("[DEBUG] Powershell command exited with code %d", res)
	if res != 0 {
		fmt.Printf("[DEBUG] Stdout: %s, Stderr: %s", stdout, stderr)
	}
	if err != nil {
		fmt.Printf("[DEBUG] run error : %s", err)
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
