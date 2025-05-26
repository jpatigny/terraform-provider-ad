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
	log.Printf("[DEBUG][memberExistsInList] Start of function.")
	for _, item := range memberList {
		if m.GUID == item.GUID {
			return true
		}
	}
	log.Printf("[DEBUG][memberExistsInList] End of function.")
	return false
}

func diffGroupMemberLists(expectedMembers, existingMembers []*Member) ([]*Member, []*Member) {
	log.Printf("[DEBUG][diffGroupMemberLists] Start of function.")
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

	log.Printf("[DEBUG][diffGroupMemberLists] End of function.")
	return toAdd, toRemove
}

func unmarshalMember(input []byte) ([]*Member, error) {
	log.Printf("[DEBUG][unmarshalMember] Start of function.")
	var m []*Member
	err := json.Unmarshal(input, &m)
	if err != nil {
		return nil, err
	}
	if len(m) > 0 && m[0].GUID == "" {
		return nil, fmt.Errorf("invalid data while unmarshalling member data, json doc was: %s", string(input))
	}
	log.Printf("[DEBUG][unmarshalMember] End of function.")
	return m, nil
}

func (g *GroupMembership) getGroupMembers(conf *config.ProviderConf) ([]*Member, error) {
	log.Printf("[DEBUG][getGroupMembers] Start of function.")
	const grpMembersTpl = `
{{- $hasGrpCred := and .Group.Username .Group.Password }}
{{- $hasGrpServer := .Group.Domain }}
$grpParams = @{
  Identity = '{{ .Group.GUID }}'
{{- if $hasGrpServer }}
  Server = '{{ .Group.Domain }}'
{{- end }}
{{- if $hasGrpCred }}
  Credential = New-Object System.Management.Automation.PSCredential ("{{ .Group.Username }}", (ConvertTo-SecureString "{{ .Group.Password }}" -AsPlainText -Force))
{{- end }}
}
try {
    $result = Get-ADGroupMember @grpParams
} catch {
    $group = Get-ADGroup -Properties Member @grpParams
    $result = foreach ($dn in $group.Member) {
	    $grpParams['Identity'] = $dn
        $ado = Get-ADObject @grpParams
        $name = if ($ado.Name -match "^S-\d-\d-\d+") {
            try {
                ([System.Security.Principal.SecurityIdentifier]$ado.Name).Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $ado.Name
            }
        } else {
            $ado.Name
        }

        [PSCustomObject]@{
            SamAccountName     = $ado.SamAccountName
            DistinguishedName  = $ado.DistinguishedName
            ObjectGUID         = $ado.ObjectGUID
            Name               = $name
        }
    }
}
$result | ConvertTo-Json
`
	tmpl, err := template.New("psScriptmbr").Parse(grpMembersTpl)
	if err != nil {
		return nil, fmt.Errorf("template parse error: %w", err)
	}
	var scriptBuf bytes.Buffer
	err = tmpl.Execute(&scriptBuf, g)
	if err != nil {
		return nil, fmt.Errorf("template execution error: %w", err)
	}

	psOpts := CreatePSCommandOpts{
		JSONOutput:      false,
		ForceArray:      true,
		ExecLocally:     conf.IsConnectionTypeLocal(),
		PassCredentials: false,
		Username:        "",
		Password:        "",
		Server:          "",
	}

	// Create the PowerShell command object
	cmd := []string{scriptBuf.String()}

	psCmd := NewPSCommand(cmd, psOpts)
	result, err := psCmd.Run(conf)
	if err != nil {
		return nil, fmt.Errorf("while running Get-ADGroupMember: %w", err)
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
	log.Printf("[DEBUG][getGroupMembers] End of function.")
	return gm, nil
}

func (g *GroupMembership) bulkGroupMembersOp(conf *config.ProviderConf, operation string, members []*Member) error {
	log.Printf("[DEBUG][bulkGroupMembersOp] Start of function with operation: %s", operation)
	if len(members) == 0 {
		return nil
	}
	const psScriptTemplate = `
{{- $hasGrpCred := and .Group.Username .Group.Password }}
{{- $hasGrpServer := .Group.Domain }}
{{- $hasMbrCred := and .GroupMember.Username .GroupMember.Password }}
{{- $hasMbrServer := .GroupMember.Domain }}
$members = @()
$grpParams = @{
  Identity = '{{ .Group.GUID }}'
{{- if $hasGrpServer }}
  Server = '{{ .Group.Domain }}'
{{- end }}
{{- if $hasGrpCred }}
  Credential = New-Object System.Management.Automation.PSCredential ("{{ .Group.Username }}", (ConvertTo-SecureString "{{ .Group.Password }}" -AsPlainText -Force))
{{- end }}
}
$group = Get-ADGroup @grpParams
$mbrParams = @{
{{- if $hasMbrServer }}
  Server = '{{ .GroupMember.Domain }}'
{{- end }}
{{- if $hasMbrCred }}
  Credential = New-Object System.Management.Automation.PSCredential ("{{ .GroupMember.Username }}", (ConvertTo-SecureString "{{ .GroupMember.Password }}" -AsPlainText -Force))
{{- end }}
}
{{- range .Members }}
$obj = try { Get-ADObject -Identity '{{ .GUID }}' @mbrParams } catch { Get-ADObject -Filter "SamAccountName -eq '{{ .GUID }}' -or SamAccountName -eq '{{ .GUID }}$'" @mbrParams }
switch ($obj.ObjectClass) {
    'computer'                        { $members += Get-ADComputer -Identity '{{ .GUID }}' @mbrParams }
    'user'                            { $members += Get-ADUser -Identity '{{ .GUID }}' @mbrParams }
    'group'                           { $members += Get-ADGroup -Identity '{{ .GUID }}' @mbrParams }
    'msDS-GroupManagedServiceAccount' { $members += Get-ADServiceAccount -Identity '{{ .GUID }}' @mbrParams }
}
{{- end }}
`
	tmpl, err := template.New("psScript").Parse(psScriptTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}
	var scriptBuf bytes.Buffer
	err = tmpl.Execute(&scriptBuf, g)
	if err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	// Add the operation command
	cmdop := fmt.Sprintf("%s -Identity $group -Members $members -Confirm:$false", operation)
	script := scriptBuf.String() + "\n" + cmdop

	// Create the PowerShell command object
	cmd := []string{script}

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

	log.Printf("[DEBUG][bulkGroupMembersOp] End of function with operation: %s", operation)
	return nil
}

func (g *GroupMembership) addGroupMembers(conf *config.ProviderConf, members []*Member) error {
	return g.bulkGroupMembersOp(conf, "Add-ADGroupMember", members)
}

func (g *GroupMembership) removeGroupMembers(conf *config.ProviderConf, members []*Member) error {
	return g.bulkGroupMembersOp(conf, "Remove-ADGroupMember", members)
}

func (g *GroupMembership) Update(conf *config.ProviderConf, expected []*Member) error {
	log.Printf("[DEBUG][Update] Start of function.")
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
	log.Printf("[DEBUG][Update] End of function.")
	return nil
}

func (g *GroupMembership) Create(conf *config.ProviderConf) error {
	log.Printf("[DEBUG][Create] Start of function.")
	if len(g.Members) == 0 {
		return nil
	}

	err := g.addGroupMembers(conf, g.Members)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG][Create] End of function.")
	return nil
}

func (g *GroupMembership) Delete(conf *config.ProviderConf) error {
	log.Printf("[DEBUG][Delete] Start of function.")
	if len(g.Members) == 0 {
		return nil
	}

	err := g.removeGroupMembers(conf, g.Members)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG][Delete] End of function.")
	return nil
}

func NewGroupMembershipFromHost(conf *config.ProviderConf, groupID string) (*GroupMembership, error) {
	log.Printf("[DEBUG][NewGroupMembershipFromHost] Start of function with groupID: %s", groupID)
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
	log.Printf("[DEBUG][NewGroupMembershipFromHost] End of function with groupID: %s", groupID)
	return result, nil
}

func NewGroupMembershipFromState(d *schema.ResourceData) (*GroupMembership, error) {
	log.Printf("[DEBUG][NewGroupMembershipFromState] Start function")
	groupSet := d.Get("group").(*schema.Set)
	membersSet := d.Get("members").(*schema.Set)

	result := &GroupMembership{
		Group:       &Grp{},
		GroupMember: &GroupMember{},
		Members:     []*Member{},
	}

	for _, g := range groupSet.List() {
		groupMap := g.(map[string]interface{})
		id := groupMap["id"].(string)

		var domain, username, password string
		if v, ok := groupMap["domain"].(string); ok {
			domain = v
		}
		if v, ok := groupMap["user"].(string); ok {
			username = v
		}
		if v, ok := groupMap["password"].(string); ok {
			password = v
		}

		log.Printf("[DEBUG][NewGroupMembershipFromState] Group ID: %s", id)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group Domain: %s", domain)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group User: %s", username)

		result.Group = &Grp{
			GUID:     id,
			Domain:   domain,
			Username: username,
			Password: password,
		}
		break
	}

	for _, m := range membersSet.List() {
		membersMap := m.(map[string]interface{})
		ids := membersMap["id"].([]interface{})

		var domain, username, password string
		if v, ok := membersMap["domain"].(string); ok {
			domain = v
		}
		if v, ok := membersMap["user"].(string); ok {
			username = v
		}
		if v, ok := membersMap["password"].(string); ok {
			password = v
		}

		log.Printf("[DEBUG][NewGroupMembershipFromState] Member Domain: %s", domain)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Member User: %s", username)

		result.GroupMember = &GroupMember{
			Domain:   domain,
			Username: username,
			Password: password,
		}

		for _, id := range ids {
			memberGUID := id.(string)
			log.Printf("[DEBUG][NewGroupMembershipFromState] Member GUID: %s", memberGUID)
			result.Members = append(result.Members, &Member{
				GUID: memberGUID,
			})
		}
		break
	}

	log.Printf("[DEBUG][NewGroupMembershipFromState] End function")
	return result, nil
}
