package winrmhelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"text/template"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Grp struct {
	GUID     string
	Domain   string
	Username string
	Password string
}

type GroupMember struct {
	Domain   string
	Username string
	Password string
}

type Member struct {
	SamAccountName string `json:"SamAccountName"`
	DN             string `json:"DistinguishedName"`
	GUID           string `json:"ObjectGUID"`
	Name           string `json:"Name"`
}

type GroupMembership struct {
	Group       *Grp
	GroupMember *GroupMember
	Members     []*Member
}

func memberExistsInList(m *Member, memberList []*Member) bool {
	for _, item := range memberList {
		if m.GUID == item.GUID {
			return true
		}
	}
	return false
}

func diffGroupMemberLists(expectedMembers, existingMembers []*Member) ([]*Member, []*Member) {
	var toAdd, toRemove []*Member
	for _, member := range expectedMembers {
		if !memberExistsInList(member, existingMembers) {
			toAdd = append(toAdd, member)
		}
	}

	for _, member := range existingMembers {
		if !memberExistsInList(member, expectedMembers) {
			toRemove = append(toRemove, member)
		}
	}

	return toAdd, toRemove
}

func unmarshalMember(input []byte) ([]*Member, error) {
	var m []*Member
	err := json.Unmarshal(input, &m)
	if err != nil {
		return nil, err
	}
	if len(m) > 0 && m[0].GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling member data, json doc was: %s", string(input))
	}
	return m, nil
}

func getMembershipList(m []*Member) string {
	out := []string{}
	for _, member := range m {
		out = append(out, member.GUID)
	}

	return strings.Join(out, ",")
}

// adapt to manage domain, user and password in command options : OK
// adapt to change output type to Member : OK
func (g *GroupMembership) getGroupMembers(conf *config.ProviderConf) ([]*Member, error) {
	cmd := fmt.Sprintf("Get-ADGroupMember -Identity %q", g.Group.GUID)
	psOpts := CreatePSCommandOpts{
		JSONOutput:      true,
		ForceArray:      true,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
	}

	if g.Group.Domain != "" {
		psOpts.Server = g.Group.Domain
	}
	if g.Group.Username != "" && g.Group.Password != "" {
		psOpts.Username = g.Group.Username
		psOpts.Password = g.Group.Password
	}

	psCmd := NewPSCommand([]string{cmd}, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return nil, fmt.Errorf("while running Get-ADGroupMember: %s", err)
	} else if result.ExitCode != 0 {
		return nil, fmt.Errorf("command Get-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
	}

	if strings.TrimSpace(result.Stdout) == "" {
		return []*Member{}, nil
	}

	gm, err := unmarshalMember([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("while unmarshalling group membership response: %s", err)
	}

	return gm, nil
}

func (g *GroupMembership) bulkGroupMembersOp(conf *config.ProviderConf, operation string, members []*Member) error {
	if len(members) == 0 {
		return nil
	}
	const psScriptTemplate = `
{{- $hasGrpCred := and .g.Group.Username .g.Group.Password }}
{{- $hasGrpServer := .g.Group.Domain }}
{{- $hasMbrCred := and .g.GroupMember.Username .g.GroupMember.Password }}
{{- $hasMbrServer := .g.GroupMember.Domain }}
$members = @()
$grpParams = @{
{{- if $hasGrpServer }}
  Server = '{{ .g.Group.Domain }}'
{{- end }}
{{- if $hasGrpCred }}
  Credential = New-Object System.Management.Automation.PSCredential ("{{ .g.Group.Username }}", (ConvertTo-SecureString "{{ .g.Group.Password }}" -AsPlainText -Force))
{{- end }}
}
$group = Get-ADGroup @grpParams 
$mbrParams = @{
{{- if $hasMbrServer }}
  Server = '{{ .g.GroupMember.Domain }}'
{{- end }}
{{- if $hasMbrCred }}
  Credential = New-Object System.Management.Automation.PSCredential ("{{ .g.GroupMember.Username }}", (ConvertTo-SecureString "{{ .g.GroupMember.Password }}" -AsPlainText -Force))
{{- end }}
}
{{- range .g.Members }}
$mbrParams['Identity'] = '{{ . }}'
$obj = Get-ADObject @mbrParams
switch ($obj.ObjectClass) {
    'computer'                        { $members += Get-ADComputer @mbrParams }
    'user'                            { $members += Get-ADUser @mbrParams }
    'group'                           { $members += Get-ADGroup @mbrParams }
    'msDS-GroupManagedServiceAccount' { $members += Get-ADServiceAccount @mbrParams }
}
{{ end }}
`
	tmpl, err := template.New("psScript").Parse(psScriptTemplate)
	if err != nil {
		panic(err)
	}
	var scriptBuf bytes.Buffer
	err = tmpl.Execute(&scriptBuf, g)
	if err != nil {
		panic(err)
	}
	script := scriptBuf.String()
	cmdop := fmt.Sprintf("%s -Identity $group -Members $members -Confirm:$false", operation)
	cmd := []string{script, cmdop}

	psOpts := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: false,
		Username:        "",
		Password:        "",
		Server:          "",
	}

	psCmd := NewPSCommand(cmd, psOpts)
	result, err := psCmd.Run(conf)

	if err != nil {
		return fmt.Errorf("while running %s: %s", operation, err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("command %s exited with a non-zero exit code(%d), stderr: %s, stdout: %s", operation, result.ExitCode, result.StdErr, result.Stdout)
	}

	return nil
}

func (g *GroupMembership) addGroupMembers(conf *config.ProviderConf, members []*Member) error {
	return g.bulkGroupMembersOp(conf, "Add-ADGroupMember", members)
}

func (g *GroupMembership) removeGroupMembers(conf *config.ProviderConf, members []*Member) error {
	return g.bulkGroupMembersOp(conf, "Remove-ADGroupMember", members)
}

func (g *GroupMembership) Update(conf *config.ProviderConf, expected []*Member) error {
	existing, err := g.getGroupMembers(conf)
	if err != nil {
		return err
	}

	toAdd, toRemove := diffGroupMemberLists(expected, existing)
	err = g.addGroupMembers(conf, toAdd)
	if err != nil {
		return err
	}

	err = g.removeGroupMembers(conf, toRemove)
	if err != nil {
		return err
	}

	return nil
}

func (g *GroupMembership) Create(conf *config.ProviderConf) error {
	if len(g.Members) == 0 {
		return nil
	}

	memberList := getMembershipList(g.Members)
	cmds := []string{fmt.Sprintf("Add-ADGroupMember -Identity %q -Members %s", g.Group.GUID, memberList)}
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
		return fmt.Errorf("while running Add-ADGroupMember: %s", err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("command Add-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
	}

	return nil
}

func (g *GroupMembership) Delete(conf *config.ProviderConf) error {
	subCmdOpt := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      false,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: conf.IsPassCredentialsEnabled(),
		Username:        conf.Settings.WinRMUsername,
		Password:        conf.Settings.WinRMPassword,
		Server:          conf.IdentifyDomainController(),
		SkipCredPrefix:  true,
	}
	subcmd := NewPSCommand([]string{fmt.Sprintf("Get-ADGroupMember %q", g.Group.GUID)}, subCmdOpt)
	cmd := fmt.Sprintf("Remove-ADGroupMember %q -Members (%s) -Confirm:$false", g.Group.GUID, subcmd.String())

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
		return fmt.Errorf("while running Remove-ADGroupMember: %s", err)
	} else if result.ExitCode != 0 && !strings.Contains(result.StdErr, "InvalidData") {
		return fmt.Errorf("command Remove-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
	}
	return nil
}

func NewGroupMembershipFromHost(conf *config.ProviderConf, groupID string) (*GroupMembership, error) {
	result := &GroupMembership{
		Group: &Grp{
			GUID: groupID,
		},
	}

	gm, err := result.getGroupMembers(conf)
	if err != nil {
		return nil, err
	}
	result.Members = gm

	return result, nil
}

func NewGroupMembershipFromState(d *schema.ResourceData) (*GroupMembership, error) {
	group := d.Get("group").(*schema.Set)
	members := d.Get("members").(*schema.Set)

	result := &GroupMembership{
		Group:       &Grp{},
		GroupMember: &GroupMember{},
		Members:     []*Member{},
	}

	for _, g := range group.List() {
		if g == "" {
			continue
		}
		id := g.(map[string]interface{})["id"]
		srv := g.(map[string]interface{})["domain"]
		user := g.(map[string]interface{})["user"]
		pass := g.(map[string]interface{})["password"]
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group ID: %s", id)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group Domain: %s", srv)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group User: %s", user)
		newGroup := &Grp{
			GUID:     id.(string),
			Domain:   srv.(string),
			Username: user.(string),
			Password: pass.(string),
		}

		result.Group = newGroup
	}

	for _, m := range members.List() {
		if m == "" {
			continue
		}

		mbrGUID := m.(map[string]interface{})["id"]
		srv := m.(map[string]interface{})["domain"]
		user := m.(map[string]interface{})["user"]
		pass := m.(map[string]interface{})["password"]

		newGroupMember := &GroupMember{
			Domain:   srv.(string),
			Username: user.(string),
			Password: pass.(string),
		}
		result.GroupMember = newGroupMember

		log.Printf("[DEBUG][NewGroupMembershipFromState] Member ID: %s", mbrGUID)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Member Domain: %s", srv)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Member User: %s", user)
		for _, m := range mbrGUID.([]interface{}) {
			newMember := &Member{
				GUID: m.(string),
			}
			result.Members = append(result.Members, newMember)
		}
	}
	resJSON, _ := json.Marshal(result)

	log.Printf("[DEBUG][NewGroupMembershipFromState] result : %s", resJSON)

	return result, nil
}
