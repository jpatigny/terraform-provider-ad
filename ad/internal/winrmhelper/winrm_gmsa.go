package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/masterzen/winrm"
)

// Gmsa represents an AD Gmsa
type Gmsa struct {
	AllowReversiblePasswordEncryption          bool
	BadLogonCount                              int
	badPasswordTime                            int
	badPwdCount                                int
	CanonicalName                              string
	CN                                         string
	Container                                  string
	CompoundIdentitySupported                  bool
	Created                                    string
	Delegated                                  bool `json:"AccountNotDelegated"`
	Description                                string
	DisplayName                                string
	DistinguishedName                          string
	DNSHostName                                string
	DoesNotRequirePreAuth                      bool
	Enabled                                    bool
	Expiration                                 string `json:"AccountExpirationDate"`
	GUID                                       string `json:"ObjectGUID"`
	HomedirRequired                            bool
	HomePage                                   string
	KerberosEncryptionType                     []string
	LastLogonDate                              string
	LockedOut                                  bool
	logonCount                                 int
	ManagedPasswordIntervalInDays              int
	Name                                       string
	PrimaryGroup                               string
	PrincipalsAllowedToDelegateToAccount       []string
	PrincipalsAllowedToRetrieveManagedPassword []string
	SAMAccountName                             string
	ServicePrincipalNames                      []string
	SID                                        string
	TrustedForDelegation                       bool
}

// NewGmsa creates the Gmsa by running the New-ADServiceAccount powershell command
func (g *Gmsa) NewGmsa(client *winrm.Client) (string, error) {
	if g.Name == "" || g.DNSHostName == "" {
		return "", fmt.Errorf("Gmsa name and dnshostname are required")
	}

	log.Printf("Adding gmsa with name: %q", g.Name)
	cmds := []string{fmt.Sprintf("New-ADServiceAccount -Passthru -Name %q DNSHostName %q", g.Name, g.DNSHostName)}

	if g.CompoundIdentitySupported == true {
		cmds = append(cmds, fmt.Sprintf("-CompoundIdentitySupported $%t", g.CompoundIdentitySupported))
	}

	if g.Container != "" {
		cmds = append(cmds, fmt.Sprintf("-Path %q", g.Container))
	}

	if g.Delegated == true {
		cmds = append(cmds, fmt.Sprintf("-AccountNotDelegated $%t", g.Delegated))
	}

	if g.Description != "" {
		cmds = append(cmds, fmt.Sprintf("-Description %q", g.Description))
	}

	if g.DisplayName != "" {
		cmds = append(cmds, fmt.Sprintf("-DisplayName %q", g.DisplayName))
	}

	cmds = append(cmds, fmt.Sprintf("-Enabled $%t", g.Enabled))

	if g.Expiration != "" {
		cmds = append(cmds, fmt.Sprintf("-AccountExpirationDate %q", g.Expiration))
	}

	if g.HomePage != "" {
		cmds = append(cmds, fmt.Sprintf("-HomePage %q", g.HomePage))
	}

	if g.KerberosEncryptionType != nil {
		cmds = append(cmds, fmt.Sprintf("-KerberosEncryptionType %q", strings.Join(g.KerberosEncryptionType, ",")))
	}

	if g.ManagedPasswordIntervalInDays != 0 {
		cmds = append(cmds, fmt.Sprintf("-ManagedPasswordIntervalInDays %q", g.ManagedPasswordIntervalInDays))
	}

	if g.PrincipalsAllowedToDelegateToAccount != nil {
		cmds = append(cmds, fmt.Sprintf("-PrincipalsAllowedToDelegateToAccount %q", strings.Join(g.PrincipalsAllowedToDelegateToAccount, ",")))
	}

	if g.PrincipalsAllowedToRetrieveManagedPassword != nil {
		cmds = append(cmds, fmt.Sprintf("-PrincipalsAllowedToRetrieveManagedPassword %q", strings.Join(g.PrincipalsAllowedToRetrieveManagedPassword, ",")))
	}

	if g.SAMAccountName != "" {
		cmds = append(cmds, fmt.Sprintf("-SamAccountName %q", g.SAMAccountName))
	}

	if g.ServicePrincipalNames != nil {
		cmds = append(cmds, fmt.Sprintf("-ServicePrincipalNames  %q", strings.Join(g.ServicePrincipalNames, ",")))
	}

	cmds = append(cmds, fmt.Sprintf("-TrustedForDelegation $%t", g.TrustedForDelegation))

	result, err := RunWinRMCommand(client, cmds, true, false)
	if err != nil {
		return "", err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		if strings.Contains(result.StdErr, "AlreadyExists") {
			return "", fmt.Errorf("there is another gmsa named %q", g.Name)
		}
		return "", fmt.Errorf("command New-ADgmsa exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	gmsa, err := unmarshallGmsa([]byte(result.Stdout))

	if err != nil {
		return "", fmt.Errorf("error while unmarshalling gmsa json document: %s", err)
	}

	return gmsa.GUID, nil
}

// ModifyGmsa updates the AD gmsa's details based on what's changed in the resource.
func (g *Gmsa) ModifyGmsa(d *schema.ResourceData, client *winrm.Client) error {
	log.Printf("Modifying gmsa: %q", g.Name)
	strKeyMap := map[string]string{
		"expiration":               "AccountExpirationDate",
		"sam_account_name":         "SamAccountName",
		"display_name":             "DisplayName",
		"description":              "Description",
		"dns_host_name":            "DNSHostName",
		"home_page":                "HomePage",
		"kerberos_encryption_type": "KerberosEncryptionType",
		"principals_allowed_to_delegate_to_account":       "PrincipalsAllowedToDelegateToAccount",
		"principals_allowed_to_retrieve_managed_password": "PrincipalsAllowedToRetrieveManagedPassword",
	}

	cmds := []string{fmt.Sprintf("Set-ADServiceAccount -Identity %q", g.GUID)}

	for k, param := range strKeyMap {
		if d.HasChange(k) {
			value := d.Get(k).(string)
			cmds = append(cmds, fmt.Sprintf("-%s %q", param, value))
		}
	}

	boolKeyMap := map[string]string{
		"delegated":                   "AccountNotDelegated ",
		"compound_identity_supported": "CompoundIdentitySupported",
		"enabled":                     "Enabled",
		"trusted_for_delegation":      "TrustedForDelegation",
	}

	for k, param := range boolKeyMap {
		if d.HasChange(k) {
			value := d.Get(k).(bool)
			cmds = append(cmds, fmt.Sprintf("-%s $%t", param, value))
		}
	}

	if len(cmds) > 1 {
		result, err := RunWinRMCommand(client, cmds, false, false)
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
			return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
		}
	}

	if d.HasChange("ServicePrincipalNames") {
		cmd := fmt.Sprintf("Set-ADServiceAccount-Identity %q -ServicePrincipalNames $null ; Set-ADServiceAccount -Identity %q -ServicePrincipalNames @{Add=%s}", strings.Join(g.ServicePrincipalNames, ","))
		result, err := RunWinRMCommand(client, []string{cmd}, false, false)
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
			return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
		}
	}

	if d.HasChange("container") {
		path := d.Get("container").(string)
		cmd := fmt.Sprintf("Move-ADObject -Identity %q -TargetPath %q", g.GUID, path)
		result, err := RunWinRMCommand(client, []string{cmd}, true, false)
		if err != nil {
			return fmt.Errorf("winrm execution failure while moving gmsa object: %s", err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("Move-ADObject exited with a non zero exit code (%d), stderr: %s", result.ExitCode, result.StdErr)
		}
	}

	return nil
}

//DeleteGmsa deletes an AD gmsa by calling Remove-ADServiceAccount
func (g *Gmsa) DeleteGmsa(client *winrm.Client) error {
	cmd := fmt.Sprintf("Remove-ADServiceAccount -Identity %s -Confirm:$false", g.GUID)
	_, err := RunWinRMCommand(client, []string{cmd}, false, false)
	if err != nil {
		// Check if the resource is already deleted
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return err
	}
	return nil
}

// GetGmsaFromResource returns a gmsa struct built from Resource data
func GetGmsaFromResource(d *schema.ResourceData) *Gmsa {

	// kerberos
	var kerb []string
	kerbtypes := d.Get("kerberos_encryption_type").(*schema.Set)
	for _, r := range kerbtypes.List() {
		kerb = append(kerb, r.(string))
	}

	// delegate
	var del []string
	delegate := d.Get("principals_allowed_to_delegate_to_account").(*schema.Set)
	for _, d := range delegate.List() {
		del = append(kerb, d.(string))
	}

	// retrieve password
	var pass []string
	passwords := d.Get("principals_allowed_to_retrieve_managed_password").(*schema.Set)
	for _, p := range passwords.List() {
		kerb = append(kerb, p.(string))
	}

	gmsa := Gmsa{
		CompoundIdentitySupported:            d.Get("compound_identity_supported").(bool),
		Container:                            SanitiseTFInput(d, "container"),
		Delegated:                            d.Get("delegated").(bool),
		Description:                          SanitiseTFInput(d, "description"),
		DisplayName:                          SanitiseTFInput(d, "display_name"),
		DNSHostName:                          SanitiseTFInput(d, "dns_host_name"),
		Enabled:                              d.Get("enabled").(bool),
		Expiration:                           SanitiseTFInput(d, "expiration"),
		GUID:                                 d.Id(),
		HomePage:                             SanitiseTFInput(d, "home_page"),
		KerberosEncryptionType:               kerb,
		ManagedPasswordIntervalInDays:        d.Get("managed_password_interval_in_days").(int),
		Name:                                 SanitiseTFInput(d, "name"),
		PrincipalsAllowedToDelegateToAccount: del,
		PrincipalsAllowedToRetrieveManagedPassword: pass,
		SAMAccountName:       SanitiseTFInput(d, "sam_account_name"),
		TrustedForDelegation: d.Get("trusted_for_delegation").(bool),
	}

	return &gmsa
}

// GetGmsaFromHost returns a gmsa struct based on data
// retrieved from the AD Domain Controller.
func GetGmsaFromHost(client *winrm.Client, guid string) (*Gmsa, error) {
	cmd := fmt.Sprintf("Get-ADServiceAccount -identity %q -properties *", guid)
	result, err := RunWinRMCommand(client, []string{cmd}, true, false)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return nil, fmt.Errorf("command Get-ADgmsa exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	g, err := unmarshallGmsa([]byte(result.Stdout))

	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling gmsa json document: %s", err)
	}

	return g, nil
}

// unmarshallGmsa unmarshalls the incoming byte array containing JSON
// into a Gmsa structure and populates all fields based on the data
// extracted.
func unmarshallGmsa(input []byte) (*Gmsa, error) {
	var gmsa Gmsa
	err := json.Unmarshal(input, &gmsa)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall a ADGmsa json document with error %q, document was %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling ADGmsa json document: %s", err)
	}
	return &gmsa, nil
}
