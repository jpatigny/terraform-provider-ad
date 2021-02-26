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
	GUID                               string `json:"ObjectGuid"`
	Domain                             string
	AllowedDNSSuffixes                 []string
	ChildDomains                       []string
	ComputersContainer                 string
	DeletedObjectsContainer            string
	DN                                 string `json:"DistinguishedName"`
	DNSRoot                            string
	DomainControllersContainer         string
	DomainMode                         int
	ForeignSecurityPrincipalsContainer string
	Forest                             string
	InfrastructureMaster               string
	LastLogonReplicationInterval       string
	LinkedGroupPolicyObjects           []string
	LostAndFoundContainer              string
	ManagedBy                          string
	Name                               string
	NetBIOSName                        string
	ParentDomain                       string
	QuotasContainer                    string
	PDCEmulator                        string
	SystemsContainer                   string
	UsersContainer                     string
	SID                                SID `json:"SID"`
}

func getDNSSUffixList(dnslist []string) string {
	out := []string{}
	for _, member := range dnslist {
		suf := fmt.Sprintf("%q", member)
		out = append(out, suf)
	}

	return strings.Join(out, ",")
}

// AddDomain creates the Domain by running the New-ADDomain powershell command
func (m *Domain) AddDomain(client *winrm.Client, execLocally bool) (string, error) {

	log.Printf("Adding DNSSuffix for domain  %q", m.Domain)
	dnslist := getDNSSUffixList(m.AllowedDNSSuffixes)

	cmds := []string{fmt.Sprintf("Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes @{Add=%s} -Confirm:$false", m.Domain, dnslist)}

	result, err := RunWinRMCommand(client, cmds, true, false, execLocally)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return "", fmt.Errorf("command Set-ADDomain with parameter DNSSuffix exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	Domain, err := unmarshallDomain([]byte(result.Stdout))
	if err != nil {
		return "", fmt.Errorf("error while unmarshalling AllowedDNSSuffixes json document: %s", err)
	}

	return Domain.GUID, nil
}

// ModifyDomain updates the AD Domain's details based on what's changed in the resource.
func (m *Domain) ModifyDomain(d *schema.ResourceData, client *winrm.Client, execLocally bool) error {
	log.Printf("Modifying DNSSuffix: %q", m.Domain)

	if d.HasChange("allowed_dns_suffixes") {
		dnslist := getDNSSUffixList(m.AllowedDNSSuffixes)
		cmd := []string{fmt.Sprintf("Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes $null -Confirm:$false ; Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes @{Add=%s} -Confirm:$false", m.Domain, m.Domain, dnslist)}
		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
			return fmt.Errorf("command Set-ADDomain exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
		}
	}

	return nil
}

// DeleteDomain deletes an AD Domain by calling Remove-ADDomain
func (m *Domain) DeleteDomain(client *winrm.Client, execLocally bool) error {
	dnslist := getDNSSUffixList(m.AllowedDNSSuffixes)

	cmds := []string{fmt.Sprintf("Set-ADDomain -Identity %q -Passthru -AllowedDNSSuffixes @{Remove=%s} -Confirm:$false", m.GUID, dnslist)}

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

// GetDomainFromResource returns a Domain struct built from Resource data
func GetDomainFromResource(d *schema.ResourceData) (*Domain, error) {
	log.Printf("[DEBUG] Start of GetDomainFromResource function")
	domain := SanitiseTFInput(d, "domain")
	dnslist := d.Get("allowed_dns_suffixes").(*schema.Set)

	var result Domain
	result.Domain = domain

	for _, v := range dnslist.List() {
		if v == "" {
			continue
		}
		result.AllowedDNSSuffixes = append(result.AllowedDNSSuffixes, v.(string))
	}
	return &result, nil
}

// GetDomainFromHost returns a Domain struct based on data
// retrieved from the AD Domain Controller.
func GetDomainFromHost(client *winrm.Client, domain string, execLocally bool) (*Domain, error) {
	cmd := []string{fmt.Sprintf("Get-ADDomain -identity %q", domain)}
	result, err := RunWinRMCommand(client, cmd, true, false, execLocally)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return nil, fmt.Errorf("command Get-ADDomain exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	u, err := unmarshallDomain([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling DNSSuffix json document: %s", err)
	}
	return u, nil
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
