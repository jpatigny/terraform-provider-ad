package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"
)

// gMSA represents an AD gMSA

type gMSA struct {
	AllowReversiblePasswordEncryption          bool
	CanonicalName                              string
	CN                                         string
	Container                                  string
	Created                                    string
	Delegated                                  bool `json:"AccountNotDelegated"`
	Description                                string
	DisplayName                                string
	DistinguishedName                          string
	DNSHostName                                string
	DoesNotRequirePreAuth                      bool
	Enabled                                    bool
	ExpirationString                           string `json:"AccountExpirationDate"`
	Expiration                                 string
	GUID                                       string `json:"ObjectGUID"`
	HomedirRequired                            bool
	HomePage                                   string
	KerberosEncryptionTypeNum                  []int `json:"KerberosEncryptionType"`
	KerberosEncryptionType                     []string
	LastLogonDate                              string
	LockedOut                                  bool
	logonCount                                 int
	ManagedPasswordIntervalInDays              int `json:"msDS-ManagedPasswordInterval"`
	Name                                       string
	PrimaryGroup                               string
	PrincipalsAllowedToDelegateToAccount       []string
	PrincipalsAllowedToRetrieveManagedPassword []string
	SAMAccountName                             string
	ServicePrincipalNames                      []string
	SID                                        SID `json:"SID"`
	TrustedForDelegation                       bool
}

func ItemExistsInList(i string, memberList []string) bool {
	for _, item := range memberList {
		if i == item {
			return true
		}
	}
	return false
}

func diffMemberLists(expectedMembers, existingMembers []string) ([]string, []string) {
	var toAdd, toRemove []string
	for _, member := range expectedMembers {
		if !ItemExistsInList(member, existingMembers) {
			toAdd = append(toAdd, member)
		}
	}

	for _, member := range existingMembers {
		if !ItemExistsInList(member, expectedMembers) {
			toRemove = append(toRemove, member)
		}
	}

	log.Printf("To add: %s", toAdd)
	log.Printf("To remove: %s", toRemove)

	return toAdd, toRemove
}

func (g *gMSA) bulkSPNMembersOp(conf *config.ProviderConf, operation string, members []string) error {
	if len(members) == 0 {
		return nil
	}

	memberList := strings.Join(members, `','`)
	cmd := fmt.Sprintf("Set-ADServiceAccount -Identity %q -ServicePrincipalNames @{%s='%s'} -Confirm:$false", g.GUID, operation, memberList)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)

	if err != nil {
		return fmt.Errorf("while running %s: %s", operation, err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("command %s exited with a non-zero exit code(%d), stderr: %s, stdout: %s", operation, result.ExitCode, result.StdErr, result.Stdout)
	}

	return nil
}

func (g *gMSA) AddSPNMembers(conf *config.ProviderConf, members []string) error {
	return g.bulkSPNMembersOp(conf, "Add", members)
}

func (g *gMSA) DelSPNMembers(conf *config.ProviderConf, members []string) error {
	return g.bulkSPNMembersOp(conf, "Remove", members)
}

// NewGmsa creates the gMSA by running the New-ADServiceAccount powershell command
func (g *gMSA) NewGmsa(conf *config.ProviderConf) (string, error) {
	if g.Name == "" || g.DNSHostName == "" || g.SAMAccountName == "" {
		return "", fmt.Errorf("Following parameters are mandatotry for gmsa resource: [Name, DNSHostName, SAMAccountName] !")
	}

	log.Printf("Adding gMSA with name: %q", g.Name)
	cmds := []string{fmt.Sprintf("New-ADServiceAccount -Passthru -Name %q", g.Name)}

	cmds = append(cmds, fmt.Sprintf("-DNSHostName %q", g.DNSHostName))
	cmds = append(cmds, fmt.Sprintf("-SamAccountName %q", g.SAMAccountName))

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

	if len(g.KerberosEncryptionType) > 0 {
		cmds = append(cmds, fmt.Sprintf("-KerberosEncryptionType '%s'", strings.Join(g.KerberosEncryptionType, `','`)))
	}

	if g.ManagedPasswordIntervalInDays != 0 {
		cmds = append(cmds, fmt.Sprintf("-ManagedPasswordIntervalInDays %d", g.ManagedPasswordIntervalInDays))
	}

	if len(g.PrincipalsAllowedToDelegateToAccount) > 0 {
		cmds = append(cmds, fmt.Sprintf("-PrincipalsAllowedToDelegateToAccount '%s'", strings.Join(g.PrincipalsAllowedToDelegateToAccount, `','`)))
	}

	if len(g.PrincipalsAllowedToRetrieveManagedPassword) > 0 {
		cmds = append(cmds, fmt.Sprintf("-PrincipalsAllowedToRetrieveManagedPassword '%s'", strings.Join(g.PrincipalsAllowedToRetrieveManagedPassword, `','`)))
	}

	if len(g.ServicePrincipalNames) > 0 {
		cmds = append(cmds, fmt.Sprintf("-ServicePrincipalNames '%s'", strings.Join(g.ServicePrincipalNames, `','`)))
	}

	cmds = append(cmds, fmt.Sprintf("-TrustedForDelegation $%t", g.TrustedForDelegation))

	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand(cmds, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		if strings.Contains(result.StdErr, "AlreadyExists") {
			return "", fmt.Errorf("there is another gMSA named %q", g.Name)
		}
		return "", fmt.Errorf("command New-ADServiceAccount exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}
	log.Printf("[DEBUG] stdout: %s", result.Stdout)
	gm, err := unmarshallGmsa([]byte(result.Stdout))
	if err != nil {
		return "", fmt.Errorf("error while unmarshalling gMSA json document: %s", err)
	}

	return gm.GUID, nil
}

// ModifyGmsa updates the AD gMSA's details based on what's changed in the resource.
func (g *gMSA) ModifyGmsa(d *schema.ResourceData, conf *config.ProviderConf) error {
	log.Printf("Modifying gMSA: %q", g.Name)
	strKeyMap := map[string]string{
		"expiration":       "AccountExpirationDate",
		"sam_account_name": "SamAccountName",
		"display_name":     "DisplayName",
		"description":      "Description",
		"dns_host_name":    "DNSHostName",
		"home_page":        "HomePage",
		"name":             "Name",
	}

	cmds := []string{fmt.Sprintf("Set-ADServiceAccount -Identity %q", g.GUID)}

	for k, param := range strKeyMap {
		if d.HasChange(k) {
			value := SanitiseTFInput(d, k)
			if value == "" {
				value = "$null"
			} else {
				value = fmt.Sprintf(`"%s"`, value)
			}
			cmds = append(cmds, fmt.Sprintf(`-%s %s`, param, value))
		}
	}

	boolKeyMap := map[string]string{
		"delegated":              "AccountNotDelegated ",
		"enabled":                "Enabled",
		"trusted_for_delegation": "TrustedForDelegation",
	}

	for k, param := range boolKeyMap {
		if d.HasChange(k) {
			value := d.Get(k).(bool)
			cmds = append(cmds, fmt.Sprintf("-%s $%t", param, value))
		}
	}

	if len(cmds) > 1 {
		psOpts := CreatePSCommandOpts{
			JSONOutput:      false,
			ForceArray:      false,
			ExecLocally:     conf.IsConnectionTypeLocal(),
			PassCredentials: conf.IsPassCredentialsEnabled(),
			Username:        conf.Settings.WinRMUsername,
			Password:        conf.Settings.WinRMPassword,
			Server:          conf.IdentifyDomainController(),
		}
		psCmd := NewPSCommand(cmds, psOpts)
		result, err := psCmd.Run(conf)

		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
			return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
		}
	}

	if d.HasChange("service_principal_names") {
		expected := []string{}
		sprinc := d.Get("service_principal_names").(*schema.Set)
		for _, s := range sprinc.List() {
			if s == "" {
				continue
			}
			expected = append(expected, fmt.Sprintf("%s", s.(string)))
		}
		if len(expected) > 0 {
			log.Printf("[DEBUG] Excpected SPN list (from files): %s", expected)

			cmd := fmt.Sprintf("Get-ADServiceAccount -identity %q -properties * | Select ServicePrincipalNames", g.GUID)
			psOpts := CreatePSCommandOpts{
				JSONOutput:      true,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand([]string{cmd}, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return err
			}

			if result.ExitCode != 0 {
				log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
				return fmt.Errorf("command Get-ADUser exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
			}

			existing, err := unmarshallGmsa([]byte(result.Stdout))
			if err != nil {
				return fmt.Errorf("error while unmarshalling user json document: %s", err)
			}

			log.Printf("[DEBUG] Existing SPN list (from AD): %q", existing.ServicePrincipalNames)

			toAdd, toRemove := diffMemberLists(expected, existing.ServicePrincipalNames)
			err = g.DelSPNMembers(conf, toRemove)
			if err != nil {
				return err
			}
			err = g.AddSPNMembers(conf, toAdd)
			if err != nil {
				return err
			}
		}
	}

	if d.HasChange("principals_allowed_to_delegate_to_account") {
		del := []string{}
		delegate := d.Get("principals_allowed_to_delegate_to_account").(*schema.Set)
		for _, d := range delegate.List() {
			if d == "" {
				continue
			}
			del = append(del, fmt.Sprintf("%q", d.(string)))
		}

		if len(del) > 0 {
			princ_del := strings.Join(del, ",")
			log.Printf("[DEBUG] Principal list: %s", princ_del)
			cmd := fmt.Sprintf("Set-ADServiceAccount -Identity %q -PrincipalsAllowedToDelegateToAccount %s", g.GUID, princ_del)
			psOpts := CreatePSCommandOpts{
				JSONOutput:      false,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand([]string{cmd}, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return fmt.Errorf("while command Set-ADServiceAccount (PrincipalsAllowedToDelegateToAccount): %s", err)
			} else if result.ExitCode != 0 {
				return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
			}
		}
	}

	if d.HasChange("principals_allowed_to_retrieve_managed_password") {
		pass := []string{}
		passwords := d.Get("principals_allowed_to_retrieve_managed_password").(*schema.Set)
		for _, p := range passwords.List() {
			if p == "" {
				continue
			}
			pass = append(pass, fmt.Sprintf("%q", p.(string)))
		}

		if len(pass) > 0 {
			princ_pass := strings.Join(pass, ",")
			log.Printf("[DEBUG] Principal list: %s", princ_pass)
			cmd := fmt.Sprintf("Set-ADServiceAccount -Identity %q -PrincipalsAllowedToRetrieveManagedPassword %s", g.GUID, princ_pass)
			psOpts := CreatePSCommandOpts{
				JSONOutput:      false,
				ForceArray:      false,
				ExecLocally:     conf.IsConnectionTypeLocal(),
				PassCredentials: conf.IsPassCredentialsEnabled(),
				Username:        conf.Settings.WinRMUsername,
				Password:        conf.Settings.WinRMPassword,
				Server:          conf.IdentifyDomainController(),
			}
			psCmd := NewPSCommand([]string{cmd}, psOpts)
			result, err := psCmd.Run(conf)
			if err != nil {
				return fmt.Errorf("while command Set-ADServiceAccount (PrincipalsAllowedToRetrieveManagedPassword): %s", err)
			} else if result.ExitCode != 0 {
				return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
			}
		}
	}

	if d.HasChange("kerberos_encryption_type") {
		krb := []string{}
		krbenc := d.Get("kerberos_encryption_type").(*schema.Set)
		for _, k := range krbenc.List() {
			if k == "" {
				continue
			}
			krb = append(krb, fmt.Sprintf("%q", strings.ToUpper(k.(string))))
		}
		kerb_enc := strings.Join(krb, ",")

		log.Printf("[DEBUG] Kerberos encryption list: %s", kerb_enc)

		cmd := fmt.Sprintf("Set-ADServiceAccount -Identity %q -KerberosEncryptionType %s", g.GUID, kerb_enc)
		psOpts := CreatePSCommandOpts{
			JSONOutput:      false,
			ForceArray:      false,
			ExecLocally:     conf.IsConnectionTypeLocal(),
			PassCredentials: conf.IsPassCredentialsEnabled(),
			Username:        conf.Settings.WinRMUsername,
			Password:        conf.Settings.WinRMPassword,
			Server:          conf.IdentifyDomainController(),
		}
		psCmd := NewPSCommand([]string{cmd}, psOpts)
		result, err := psCmd.Run(conf)
		if err != nil {
			return fmt.Errorf("while command Set-ADServiceAccount (KerberosEncryptionType): %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Set-ADServiceAccount exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}

	if d.HasChange("container") {
		path := d.Get("container").(string)
		cmd := fmt.Sprintf("Move-ADObject -Identity %q -TargetPath %q", g.GUID, path)
		psOpts := CreatePSCommandOpts{
			JSONOutput:      false,
			ForceArray:      false,
			ExecLocally:     conf.IsConnectionTypeLocal(),
			PassCredentials: conf.IsPassCredentialsEnabled(),
			Username:        conf.Settings.WinRMUsername,
			Password:        conf.Settings.WinRMPassword,
			Server:          conf.IdentifyDomainController(),
		}
		psCmd := NewPSCommand([]string{cmd}, psOpts)
		result, err := psCmd.Run(conf)
		if err != nil {
			return fmt.Errorf("while command Move-ADObject: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Move-ADObject exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}

	return nil
}

// DeleteGmsa deletes an AD gMSA by calling Remove-ADServiceAccount
func (g *gMSA) DeleteGmsa(conf *config.ProviderConf) error {
	cmd := fmt.Sprintf("Remove-ADServiceAccount -Identity %s -Confirm:$false", g.GUID)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	_, err := psCmd.Run(conf)
	if err != nil {
		// Check if the resource is already deleted
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return err
	}
	return nil
}

// GetGmsaFromResource returns a gMSA struct built from Resource data
func GetGmsaFromResource(d *schema.ResourceData) (*gMSA, error) {
	gMSA := gMSA{
		Container:                     SanitiseTFInput(d, "container"),
		Delegated:                     d.Get("delegated").(bool),
		Description:                   SanitiseTFInput(d, "description"),
		DisplayName:                   SanitiseTFInput(d, "display_name"),
		DNSHostName:                   SanitiseTFInput(d, "dns_host_name"),
		Enabled:                       d.Get("enabled").(bool),
		Expiration:                    SanitiseTFInput(d, "expiration"),
		GUID:                          SanitiseTFInput(d, "guid"),
		HomePage:                      SanitiseTFInput(d, "home_page"),
		ManagedPasswordIntervalInDays: d.Get("managed_password_interval_in_days").(int),
		Name:                          SanitiseTFInput(d, "name"),
		SAMAccountName:                SanitiseTFInputLight(d, "sam_account_name"),
		TrustedForDelegation:          d.Get("trusted_for_delegation").(bool),
	}

	// delegate
	del := []string{}
	delegate := d.Get("principals_allowed_to_delegate_to_account").(*schema.Set)
	for _, d := range delegate.List() {
		if d == "" {
			continue
		}
		del = append(del, SanitiseDN(d.(string)))
	}
	if del != nil {
		gMSA.PrincipalsAllowedToDelegateToAccount = del
	}

	// principal(s)
	pass := []string{}
	passwords := d.Get("principals_allowed_to_retrieve_managed_password").(*schema.Set)
	for _, p := range passwords.List() {
		if p == "" {
			continue
		}
		pass = append(pass, SanitiseDN(p.(string)))
	}

	if pass != nil {
		gMSA.PrincipalsAllowedToRetrieveManagedPassword = pass
	}

	// Kerberos
	krb := []string{}
	krbenc := d.Get("kerberos_encryption_type").(*schema.Set)
	for _, k := range krbenc.List() {
		if k == "" {
			continue
		}
		krb = append(krb, strings.ToUpper(k.(string)))
	}

	if krb != nil {
		gMSA.KerberosEncryptionType = krb
	}

	// SPN
	spns := []string{}
	spnlist := d.Get("service_principal_names").(*schema.Set)
	for _, s := range spnlist.List() {
		if s == "" {
			continue
		}
		spns = append(spns, s.(string))
	}

	if spns != nil {
		gMSA.ServicePrincipalNames = spns
	}

	return &gMSA, nil
}

// GetGmsaFromHost returns a gMSA struct based on data
// retrieved from the AD Domain Controller.
func GetGmsaFromHost(conf *config.ProviderConf, guid string) (*gMSA, error) {
	cmd := fmt.Sprintf("Get-ADServiceAccount -identity %q -properties *", guid)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}
	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		log.Printf("[DEBUG] stderr: %s\nstdout: %s", result.StdErr, result.Stdout)
		return nil, fmt.Errorf("command Get-ADUser exited with a non-zero exit code %d, stderr: %s", result.ExitCode, result.StdErr)
	}

	g, err := unmarshallGmsa([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling user json document: %s", err)
	}
	return g, nil
}

// unmarshallGmsa unmarshalls the incoming byte array containing JSON
// into a gMSA structure and populates all fields based on the data
// extracted.
func unmarshallGmsa(input []byte) (*gMSA, error) {
	log.Printf("[DEBUG] Starting unmarshal gMSA...")
	var g gMSA
	err := json.Unmarshal(input, &g)
	if err != nil {
		log.Printf("[DEBUG] Failed to unmarshall a ADGmsa json document with error %q, document was %s", err, string(input))
		return nil, fmt.Errorf("failed while unmarshalling ADGmsa json document: %s", err)
	}
	if g.GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling Gmsa data, json doc was: %s", string(input))
	}

	commaIdx := strings.Index(g.DistinguishedName, ",")
	g.Container = g.DistinguishedName[commaIdx+1:]

	if g.ExpirationString != "" {
		log.Printf("[DEBUG] unmarshall :: converting expiration date to proper format (current value: %s)", g.ExpirationString)
		var regdate = regexp.MustCompile(`^\/Date\((.+)\)\/$`)
		// extract unixtime date
		match := regdate.FindStringSubmatch(g.ExpirationString)

		if len(match) == 0 {
			return nil, fmt.Errorf("Failed to unmarshall a ADGmsa json, expiration date format is not matching regex.")
		}

		log.Printf("[DEBUG] unmarshall :: unixtimestamp extracted from AccountExpirationDate attribute: %q", match[1])
		// convert string date to int64
		log.Printf("[DEBUG] unmarshall :: converting unixtimestamp to %s int64", match[1])
		n, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed while unmarshalling ADGmsa json document: %s", err)
		}
		// convert unix_timestamp to RFC3339
		log.Printf("[DEBUG] unmarshall :: converting unixtimestamp int64 to RFC3339")
		t := time.Unix(0, n*int64(time.Millisecond))
		tst := t.Format(time.RFC3339)
		log.Printf("[DEBUG] unmarshall :: converted unixtimestamp to RFC3339 : %s", tst)
		g.Expiration = tst
	}

	var krblistMap = map[int][]string{
		4:  {"RC4"},
		8:  {"AES128"},
		12: {"RC4", "AES128"},
		16: {"AES256"},
		20: {"RC4", "AES256"},
		24: {"AES128", "AES256"},
		28: {"RC4", "AES128", "AES256"},
	}

	log.Printf("[DEBUG] Converting Keberos encryption type number to string slice")
	for _, k := range g.KerberosEncryptionTypeNum {
		g.KerberosEncryptionType = krblistMap[k]
	}
	log.Printf("[DEBUG] Keberos slice list : %s", g.KerberosEncryptionType)
	log.Printf("[DEBUG] finsihed unmarshal gMSA...")

	return &g, nil
}
