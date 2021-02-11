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
	cmd := []string{fmt.Sprintf("Get-ADGroupMember -Identity %q", g.Group.GUID)}
	if g.Group.Domain != "" {
		cmd = append(cmd, fmt.Sprintf("-Server %q", g.Group.Domain))
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
		cmdgetgrp = []string{fmt.Sprintf("try { $group = Get-ADObject -Server %q -Identity %q } catch { $group = Get-ADObject -Server %q -Filter \"SamAccountName -eq `\"%s`\"\"}", g.Group.Domain, g.Group.GUID, g.Group.Domain, g.Group.GUID)}
	} else {
		cmdgetgrp = []string{fmt.Sprintf("try { $group = Get-ADObject -Identity %q } catch { $group = Get-ADObject -Filter \"SamAccountName -eq `\"%s`\"\"}", g.Group.GUID, g.Group.GUID)}
	}
	cmdgetgrp = append(cmdgetgrp, "; ")
	log.Printf("[DEBUG][bulkGroupMembersOp] cmdlet to get group : %s", cmdgetgrp)

	for _, m := range members {
		// get member
		var cmdgetmbr []string
		if m.Domain != "" {
			cmdgetmbr = []string{fmt.Sprintf("try { $member = Get-ADObject -Server %q -Identity %q } catch { $member = Get-ADObject -Server %q -Filter \"SamAccountName -eq `\"%s`\"\"}", m.Domain, m.GUID, m.Domain, m.GUID)}
		} else {
			cmdgetmbr = []string{fmt.Sprintf("try { $member = Get-ADObject -Identity %q } catch { $member = Get-ADObject -Filter \"SamAccountName -eq `\"%s`\"\"}", m.GUID, m.GUID)}
		}
		cmdgetmbr = append(cmdgetmbr, "; ")

		// action
		cmdaction := []string{fmt.Sprintf("Set-ADGroup -Identity %q -%s @{ 'member' = $member.DistinguishedName }", g.Group.GUID, operation)}
		if g.Group.Domain != "" {
			cmdaction = append(cmdaction, fmt.Sprintf("-Server %q", g.Group.Domain))
		}
		cmdaction = append(cmdaction, "; ")

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, cmdaction...)
		log.Printf("[DEBUG][bulkGroupMembersOp] cmdlet to be executed : %s", cmd)

		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Set-ADGroup %s : %s", operation, err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Set-ADGroup %s exited with a non-zero exit code(%d), stderr: %s, stdout: %s", operation, result.ExitCode, result.StdErr, result.Stdout)
		}
	}
	log.Printf("[DEBUG] End of bulkGroupMembersOp function")
	return nil
}

func (g *GroupMembership) addGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Add", members, execLocally)
}

func (g *GroupMembership) removeGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Remove", members, execLocally)
}

func (g *GroupMembership) Update(client *winrm.Client, expected []*GroupMember, execLocally bool) error {
	log.Printf("[DEBUG] Start Update function")
	existing, err := g.getGroupMembers(client, execLocally)
	if err != nil {
		return err
	}

	toAdd, toRemove := diffGroupMemberLists(expected, existing)
	err = g.addGroupMembers(client, toAdd, execLocally)
	if err != nil {
		return err
	}

	err = g.removeGroupMembers(client, toRemove, execLocally)
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
		cmdgetgrp = []string{fmt.Sprintf("try { $group = Get-ADObject -Server %q -Identity %q } catch { $group = Get-ADObject -Server %q -Filter \"SamAccountName -eq `\"%s`\"\"}", g.Group.Domain, g.Group.GUID, g.Group.Domain, g.Group.GUID)}
	} else {
		cmdgetgrp = []string{fmt.Sprintf("try { $group = Get-ADObject -Identity %q } catch { $group = Get-ADObject -Filter \"SamAccountName -eq `\"%s`\"\"}", g.Group.GUID, g.Group.GUID)}
	}
	cmdgetgrp = append(cmdgetgrp, "; ")

	for _, m := range g.GroupMembers {
		// get member
		var cmdgetmbr []string
		if m.Domain != "" {
			cmdgetmbr = []string{fmt.Sprintf("try { $member = Get-ADObject -Server %q -Identity %q } catch { $member = Get-ADObject -Server %q -Filter \"SamAccountName -eq `\"%s`\"\"}", m.Domain, m.GUID, m.Domain, m.GUID)}
		} else {
			cmdgetmbr = []string{fmt.Sprintf("try { $member = Get-ADObject -Identity %q } catch { $member = Get-ADObject -Filter \"SamAccountName -eq `\"%s`\"\"}", m.GUID, m.GUID)}
		}
		cmdgetmbr = append(cmdgetmbr, "; ")

		// add member
		cmdadd := []string{fmt.Sprintf("Set-ADGroup -Identity $group -Add @{ 'member' = $member.DistinguishedName }")}
		if g.Group.Domain != "" {
			cmdadd = append(cmdadd, fmt.Sprintf("-Server %q", g.Group.Domain))
		}
		cmdadd = append(cmdadd, "; ")

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, cmdadd...)

		log.Printf("[DEBUG][Create] cmdlet to be executed : %s", cmd)
		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Set-ADGroup Add: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Set-ADGroup Add exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}
	log.Printf("[DEBUG] End of Create function")
	return nil
}

func (g *GroupMembership) Delete(client *winrm.Client, execLocally bool) error {
	log.Printf("[DEBUG] Start of Delete function")
	// get group
	cmdgetgrp := []string{fmt.Sprintf("$group = Get-ADObject -Identity %q", g.Group.GUID)}
	if g.Group.Domain != "" {
		cmdgetgrp = append(cmdgetgrp, fmt.Sprintf("-Server %q", g.Group.Domain))
	}
	cmdgetgrp = append(cmdgetgrp, "; ")

	for _, m := range g.GroupMembers {
		// get member to a
		cmdgetmbr := []string{fmt.Sprintf("$member = Get-ADObject -Identity %q", m.GUID)}
		if m.Domain != "" {
			cmdgetmbr = append(cmdgetmbr, fmt.Sprintf("-Server %q", m.Domain))
		}
		cmdgetmbr = append(cmdgetmbr, "; ")

		// remove member
		cmddel := []string{fmt.Sprintf("Set-ADGroup -Identity $group -Remove @{ 'member' = $member.DistinguishedName }")}
		if g.Group.Domain != "" {
			cmddel = append(cmddel, fmt.Sprintf("-Server %q", g.Group.Domain))
		}
		cmddel = append(cmddel, "; ")

		// concat to one ps command
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, cmddel...)

		log.Printf("[DEBUG][Create] cmdlet to be executed : %s", cmd)
		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Set-ADGroup Remove: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Set-ADGroup Remove exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
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

		for _, m := range mbrGUID.([]interface{}) {
			newMember := &GroupMember{
				GUID:   m.(string),
				Domain: srv.(string),
			}
			result.GroupMembers = append(result.GroupMembers, newMember)
		}
	}
	log.Printf("[DEBUG][NewGroupMembershipFromState] result : %s", result)
	return result, nil
}
