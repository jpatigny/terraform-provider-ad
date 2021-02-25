package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/masterzen/winrm"
)

// Domain represents an AD Domain
type Domain struct {
	Domain             string `json:"DNSRoot"`
	AllowedDNSSuffixes []string
}

// AddDNSSuffix
func (m *Domain) AddDNSSuffix(client *winrm.Client, execLocally bool) (string, error) {

	log.Printf("Adding DNSSuffix for domain  %q", m.Domain)
	dnslist := strings.Join(m.AllowedDNSSuffixes, "")
	cmds := []string{fmt.Sprintf("Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes @{Add=%q} -Confirm:$false", m.Domain, dnslist)}

	result, err := RunWinRMCommand(client, cmds, true, false, execLocally)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return "", fmt.Errorf("command Set-ADDomain with parameter DNSSuffix exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	return dnslist, nil
}

// DeleteDNSSuffix
func (m *Domain) DeleteDNSSuffix(client *winrm.Client, execLocally bool) error {
	dnslist := strings.Join(m.AllowedDNSSuffixes, "")
	cmds := []string{fmt.Sprintf("Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes @{Remove=%q} -Confirm:$false", m.Domain, dnslist)}
	result, err := RunWinRMCommand(client, cmds, true, false, execLocally)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return fmt.Errorf("command Set-ADDomain with parameter DNSSuffix exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	return nil
}

// GetDNSSuffixFromResource returns a Domain struct built from Resource data
func GetDNSSuffixFromResource(d *schema.ResourceData) (*Domain, error) {
	log.Printf("[DEBUG] Start of GetDNSSuffixFromResource function")
	domain := SanitiseTFInput(d, "domain")
	dnssuffix := SanitiseTFInput(d, "allowed_dns_suffix")
	var dnslist []string
	dnslist = append(dnslist, dnssuffix)

	var result Domain
	result.Domain = domain
	result.AllowedDNSSuffixes = dnslist

	return &result, nil
}

// GetDomainFromHost returns a Domain struct based on data
// retrieved from the AD Domain Controller.
func GetDNSSuffixFromHost(client *winrm.Client, domain string, dnssuffix string, execLocally bool) (*Domain, error) {
	cmddomain := []string{fmt.Sprintf("(Get-ADDomain -identity %q).DNSRoot", domain)}
	cmddns := []string{fmt.Sprintf("(Get-ADDomain -identity %q).AllowedDNSSuffixes | Where-Object { $_ -eq %q }", domain, dnssuffix)}

	resultdom, err := RunWinRMCommand(client, cmddomain, false, false, execLocally)
	if err != nil {
		return nil, err
	}

	if resultdom.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", resultdom.StdErr, resultdom.Stdout)
		return nil, fmt.Errorf("command Get-ADDomain DNSRoot exited with a non-zero exit code %d, stderr: %s", resultdom.ExitCode, resultdom.StdErr)
	}

	resultdns, err := RunWinRMCommand(client, cmddns, true, true, execLocally)
	if err != nil {
		return nil, err
	}

	if resultdns.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", resultdns.StdErr, resultdns.Stdout)
		return nil, fmt.Errorf("command Get-ADDomain AllowedDNSSuffixes exited with a non-zero exit code %d, stderr: %s", resultdns.ExitCode, resultdns.StdErr)
	}

	result, err := unmarshallDomain([]byte(resultdns.Stdout))
	if err != nil {
		return nil, fmt.Errorf("while unmarshalling dnssuffix list response: %s", err)
	}

	return result, nil
}

func unmarshallDomain(input []byte) (*Domain, error) {
	var dom Domain
	err := json.Unmarshal(input, &dom)
	if err != nil {
		log.Printf("[ERROR] Failed to unmarshall json document with error %q, document was: %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling json response: %s", err)
	}
	return &dom, nil

}
