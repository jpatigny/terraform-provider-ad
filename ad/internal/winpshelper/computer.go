// NewComputerFromHost return a new Machine struct populated from data we get
// from the domain controller
func NewComputerFromHost(conn *winrm.Client, identity string) (*Computer, error) {
	cmd := fmt.Sprintf("Get-ADComputer -Identity %q -Properties *", identity)
	result, err := RunWinRMCommand(conn, []string{cmd}, true, false)
	if err != nil {
		return nil, fmt.Errorf("winrm execution failure in NewComputerFromHost: %s", err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("Get-ADComputer exited with a non zero exit code (%d), stderr: %s", result.ExitCode, result.StdErr)
	}
	computer, err := unmarshallComputer([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("NewComputerFromHost: %s", err)
	}
	computer.Path = strings.TrimPrefix(computer.DN, fmt.Sprintf("CN=%s,", computer.Name))

	return computer, nil
}