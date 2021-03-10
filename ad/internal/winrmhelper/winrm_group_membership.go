package winrmhelper

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/masterzen/winrm"
)

type Grp struct {
	GUID   string
	Domain string
}

type GroupMembership struct {
	Group        *Grp
	GroupMembers []*GroupMember
}

type GroupMember struct {
	SamAccountName string `json:"SamAccountName"`
	DN             string `json:"DistinguishedName"`
	GUID           string `json:"ObjectGUID"`
	Name           string `json:"Name"`
	Domain         string
}

func getadgroup(domain string, identity string) []string {
	cmd := []string{fmt.Sprintf("$group = Get-ADGroup -Identity %q", identity)}
	if domain != "" {
		cmd = append(cmd, fmt.Sprintf("-Server %q", domain))
	}
	cmd = append(cmd, fmt.Sprintf("\n"))
	return cmd
}

func getadmember(domain string, identity string) []string {
	var member []string

	if domain != "" {
		member = []string{fmt.Sprintf(`try { 
	$member = Get-ADObject -Server %q -Identity %q 
} catch { 
	$member = Get-ADObject -Server %q -Filter "SamAccountName -eq '%s' -or SamAccountName -eq '%s$'"
}
switch ($member.ObjectClass) {
	'computer'                        { $member = Get-ADComputer -Server %q -Identity %q }
	'user'                            { $member = Get-ADUser -Server %q -Identity %q }
	'group'                           { $member = Get-ADGroup -Server %q -Identity %q }
	'msDS-GroupManagedServiceAccount' { $member = Get-ADServiceAccount -Server %q -Identity %q }
}`, domain, identity, domain, identity, identity, domain, identity, domain, identity, domain, identity, domain, identity)}
	} else {
		member = []string{fmt.Sprintf(`try { 
	$member = Get-ADObject -Identity %q 
} catch { 
	$member = Get-ADObject -Filter "SamAccountName -eq '%s' -or SamAccountName -eq '%s$'"
}
switch ($member.ObjectClass) {
	'computer'                        { $member = Get-ADComputer -Identity %q }
	'user'                            { $member = Get-ADUser -Identity %q }
	'group'                           { $member = Get-ADGroup -Identity %q }
	'msDS-GroupManagedServiceAccount' { $member = Get-ADServiceAccount -Identity %q }
}`, identity, identity, identity, identity, identity, identity, identity)}
	}
	member = append(member, fmt.Sprintf("\n"))
	return member
}

func groupExistsInList(g *GroupMember, memberList []*GroupMember) bool {
	for _, item := range memberList {
		if g.GUID == item.GUID {
			return true
		}
	}
	return false
}

func diffGroupMemberLists(expectedMembers, existingMembers []*GroupMember) ([]*GroupMember, []*GroupMember) {
	var toAdd, toRemove []*GroupMember
	for _, member := range expectedMembers {
		if !groupExistsInList(member, existingMembers) {
			toAdd = append(toAdd, member)
		}
	}

	for _, member := range existingMembers {
		if !groupExistsInList(member, expectedMembers) {
			toRemove = append(toRemove, member)
		}
	}

	return toAdd, toRemove
}

func unmarshalGroupMembership(input []byte) ([]*GroupMember, error) {
	var gm []*GroupMember
	err := json.Unmarshal(input, &gm)
	if err != nil {
		return nil, err
	}

	return gm, nil
}

func getMembershipList(g []*GroupMember) string {
	out := []string{}
	for _, member := range g {
		guid := fmt.Sprintf("%q", member.GUID)
		out = append(out, guid)
	}

	return strings.Join(out, ",")
}

func (g *GroupMembership) getGroupMembers(client *winrm.Client, execLocally bool) ([]*GroupMember, error) {
	log.Printf("[DEBUG] Start getGroupMembers function")
	log.Printf("[DEBUG][getGroupMembers] Group GUID: %s", g.Group.GUID)
	var cmd []string
	if g.Group.Domain != "" {
		log.Printf("[DEBUG][getGroupMembers] Domain: %s", g.Group.Domain)
		cmd = []string{fmt.Sprintf(`try {
$result = Get-ADGroupMember -Identity %q -Server %q
}
catch {
	$translatedMembers = @()
	$members = (Get-ADGroup %q -Properties member -Server %q).member
	foreach($m in $members) {
		$name = ""
		$dn = $([adsi]$("LDAP://$m")).DistinguishedName
		$ado = Get-ADObject -Identity $($dn)
		if ($ado.Name -match "^S-\d-\d-\d\d") {
			try {
				$name =  ([System.Security.Principal.SecurityIdentifier] $ado.Name).Translate([System.Security.Principal.NTAccount]).Value
			}
			catch {
				$name = $ado.Name
			}
		}
		else {
		  $name = $ado.Name
		}
		$translatedMembers += [PSCustomObject] @{
		  SamAccountName = $ado.SamAccountName
		  DistinguishedName = $ado.DistinguishedName
		  objectGUID = $ado.ObjectGUID
		  Name = $name
		}
	}
	$result = $translatedMembers
}
$result`, g.Group.GUID, g.Group.Domain, g.Group.GUID, g.Group.Domain)}
	} else {
		cmd = []string{fmt.Sprintf(`try {
$result = Get-ADGroupMember -Identity %q
}
catch {
	$translatedMembers = @()
	$members = (Get-ADGroup %q -Properties member).member
	foreach($m in $members) {
		$name = ""
		$dn = $([adsi]$("LDAP://$m")).DistinguishedName
		$ado = Get-ADObject -Identity $($dn)
		if ($ado.Name -match "^S-\d-\d-\d\d") {
			try {
				$name =  ([System.Security.Principal.SecurityIdentifier] $ado.Name).Translate([System.Security.Principal.NTAccount]).Value
			}
			catch {
				$name = $ado.Name
			}
		}
		else {
			$name = $ado.Name
		}
		$translatedMembers += [PSCustomObject] @{
			SamAccountName = $ado.SamAccountName
			DistinguishedName = $ado.DistinguishedName
			objectGUID = $ado.ObjectGUID
			Name = $name
		}
	}
	$result = $translatedMembers
}
$result`, g.Group.GUID, g.Group.GUID)}
	}
	result, err := RunWinRMCommand(client, cmd, true, true, execLocally)
	if err != nil {
		return nil, fmt.Errorf("while running Get-ADGroupMember: %s", err)
	} else if result.ExitCode != 0 {
		return nil, fmt.Errorf("command Get-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
	}

	if strings.TrimSpace(result.Stdout) == "" {
		return []*GroupMember{}, nil
	}
	log.Printf("[DEBUG][getGroupMembers] stdout : %s", result.Stdout)

	gm, err := unmarshalGroupMembership([]byte(result.Stdout))
	if err != nil {
		return nil, fmt.Errorf("while unmarshalling group membership response: %s", err)
	}
	log.Printf("[DEBUG] End of getGroupMembers function")
	return gm, nil
}

func (g *GroupMembership) bulkGroupMembersOp(client *winrm.Client, operation string, members []*GroupMember, execLocally bool) error {
	log.Printf("[DEBUG] Start bulkGroupMembersOp function")
	if len(members) == 0 {
		return nil
	}

	// get group
	var cmdgetgrp []string

	if g.Group.Domain != "" {
		cmdgetgrp = getadgroup(g.Group.Domain, g.Group.GUID)
	} else {
		cmdgetgrp = getadgroup("", g.Group.GUID)
	}

	for _, m := range members {

		// get member
		var cmdgetmbr []string
		if m.Domain != "" {
			cmdgetmbr = getadmember(m.Domain, m.GUID)
		} else {
			cmdgetmbr = getadmember("", m.GUID)
		}

		// action
		cmdaction := []string{fmt.Sprintf("%s -Identity $group -Members $member -Confirm:$false", operation)}
		if g.Group.Domain != "" {
			cmdaction = append(cmdaction, fmt.Sprintf("-Server %q", g.Group.Domain))
		}

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, cmdaction...)
		log.Printf("[DEBUG][bulkGroupMembersOp] cmdlet to be executed : %s", cmd)

		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running %s : %s", operation, err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command %s exited with a non-zero exit code(%d), stderr: %s, stdout: %s", operation, result.ExitCode, result.StdErr, result.Stdout)
		}
	}
	log.Printf("[DEBUG] End of bulkGroupMembersOp function")
	return nil
}

func (g *GroupMembership) addGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Add-ADGroupMember", members, execLocally)
}

func (g *GroupMembership) removeGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Remove-ADGroupMember", members, execLocally)
}

func (g *GroupMembership) Update(client *winrm.Client, expected []*GroupMember, execLocally bool) error {
	log.Printf("[DEBUG] Start Update function")
	existing, err := g.getGroupMembers(client, execLocally)
	if err != nil {
		return err
	}

	toAdd, toRemove := diffGroupMemberLists(expected, existing)
	err = g.removeGroupMembers(client, toRemove, execLocally)
	if err != nil {
		return err
	}
	err = g.addGroupMembers(client, toAdd, execLocally)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] End of Update function")
	return nil
}

func (g *GroupMembership) Create(client *winrm.Client, execLocally bool) error {
	log.Printf("[DEBUG] Start Create function")
	if len(g.GroupMembers) == 0 {
		return nil
	}

	// get group
	var cmdgetgrp []string

	if g.Group.Domain != "" {
		cmdgetgrp = getadgroup(g.Group.Domain, g.Group.GUID)
	} else {
		cmdgetgrp = getadgroup("", g.Group.GUID)
	}

	for _, m := range g.GroupMembers {

		// get member
		var cmdgetmbr []string
		if m.Domain != "" {
			cmdgetmbr = getadmember(m.Domain, m.GUID)
		} else {
			cmdgetmbr = getadmember("", m.GUID)
		}

		// add
		add := []string{fmt.Sprintf("Add-ADGroupMember -Identity $group -Members $member -Confirm:$false")}
		if g.Group.Domain != "" {
			add = append(add, fmt.Sprintf("-Server %q", g.Group.Domain))
		}

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, add...)

		log.Printf("[DEBUG][Create] cmdlet to be executed : %s", cmd)
		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Add-ADGroupMember: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Add-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}
	log.Printf("[DEBUG] End of Create function")
	return nil
}

func (g *GroupMembership) Delete(client *winrm.Client, execLocally bool) error {
	log.Printf("[DEBUG] Start of Delete function")
	// get group
	var cmdgetgrp []string

	if g.Group.Domain != "" {
		cmdgetgrp = getadgroup(g.Group.Domain, g.Group.GUID)
	} else {
		cmdgetgrp = getadgroup("", g.Group.GUID)
	}

	for _, m := range g.GroupMembers {
		// get member
		var cmdgetmbr []string
		if m.Domain != "" {
			cmdgetmbr = getadmember(m.Domain, m.GUID)
		} else {
			cmdgetmbr = getadmember("", m.GUID)
		}

		// remove
		del := []string{fmt.Sprintf("Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false")}
		if g.Group.Domain != "" {
			del = append(del, fmt.Sprintf("-Server %q", g.Group.Domain))
		}

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, del...)

		log.Printf("[DEBUG][Delete] cmdlet to be executed : %s", cmd)
		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Remove-ADGroupMember: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Remove-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}
	log.Printf("[DEBUG] End of Delete function")
	return nil
}

func NewGroupMembershipFromHost(client *winrm.Client, groupID string, execLocally bool) (*GroupMembership, error) {
	result := &GroupMembership{
		Group: &Grp{
			GUID: groupID,
		},
	}

	gm, err := result.getGroupMembers(client, execLocally)
	if err != nil {
		return nil, err
	}
	result.GroupMembers = gm

	return result, nil
}

func NewGroupMembershipFromState(d *schema.ResourceData) (*GroupMembership, error) {
	log.Printf("[DEBUG] Start of NewGroupMembershipFromState function")
	group := d.Get("group").(*schema.Set)
	members := d.Get("members").(*schema.Set)

	result := &GroupMembership{
		Group:        &Grp{},
		GroupMembers: []*GroupMember{},
	}

	for _, g := range group.List() {
		if g == "" {
			continue
		}
		id := g.(map[string]interface{})["id"]
		srv := g.(map[string]interface{})["domain"]
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group ID: %s", id)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Group Domain: %s", srv)
		newGroup := &Grp{
			GUID:   id.(string),
			Domain: srv.(string),
		}

		result.Group = newGroup
	}

	for _, m := range members.List() {
		if m == "" {
			continue
		}

		mbrGUID := m.(map[string]interface{})["id"]
		srv := m.(map[string]interface{})["domain"]
		log.Printf("[DEBUG][NewGroupMembershipFromState] Member ID: %s", mbrGUID)
		log.Printf("[DEBUG][NewGroupMembershipFromState] Member Domain: %s", srv)
		for _, m := range mbrGUID.([]interface{}) {
			newMember := &GroupMember{
				GUID:   m.(string),
				Domain: srv.(string),
			}
			result.GroupMembers = append(result.GroupMembers, newMember)
		}
	}
	resJSON, _ := json.Marshal(result)

	log.Printf("[DEBUG][NewGroupMembershipFromState] result : %s", resJSON)
	return result, nil
}
