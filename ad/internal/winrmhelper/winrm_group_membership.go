package winrmhelper

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/masterzen/winrm"
)

type Grp struct {
	GUID   string
	Server string
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
	Server         string
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
	cmd := []string{fmt.Sprintf("Get-ADGroupMember -Identity %q", g.Group.GUID)}
	if g.Group.Server != "" {
		cmd = append(cmd, fmt.Sprintf("-Server %q", g.Group.Server))
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

	return gm, nil
}

func (g *GroupMembership) bulkGroupMembersOp(client *winrm.Client, operation string, members []*GroupMember, execLocally bool) error {
	if len(members) == 0 {
		return nil
	}

	memberList := getMembershipList(members)
	cmd := []string{fmt.Sprintf("%s -Identity %q %s -Confirm:$false", operation, g.Group.GUID, memberList)}
	if g.Group.Server != "" {
		cmd = append(cmd, fmt.Sprintf("-Server %q", g.Group.Server))
	}

	result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
	if err != nil {
		return fmt.Errorf("while running %s: %s", operation, err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("command %s exited with a non-zero exit code(%d), stderr: %s, stdout: %s", operation, result.ExitCode, result.StdErr, result.Stdout)
	}

	return nil
}

func (g *GroupMembership) addGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Add-ADGroupMember", members, execLocally)
}

func (g *GroupMembership) removeGroupMembers(client *winrm.Client, members []*GroupMember, execLocally bool) error {
	return g.bulkGroupMembersOp(client, "Remove-ADGroupMember", members, execLocally)
}

func (g *GroupMembership) Update(client *winrm.Client, expected []*GroupMember, execLocally bool, server string) error {
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

	return nil
}

func (g *GroupMembership) Create(client *winrm.Client, execLocally bool, server string) error {
	if len(g.GroupMembers) == 0 {
		return nil
	}

	// get group
	cmdgetgrp := []string{fmt.Sprintf("$group = Get-ADObject -Object %q", g.Group.GUID)}
	if g.Group.Server != "" {
		cmdgetgrp = append(cmdgetgrp, fmt.Sprintf("-Server %q", g.Group.Server))
	}
	cmdgetgrp = append(cmdgetgrp, "; ")

	for _, m := range g.GroupMembers {
		// get member
		cmdgetmbr := []string{fmt.Sprintf("$member = Get-ADObject -Object %q", m.GUID)}
		if m.Server != "" {
			cmdgetmbr = append(cmdgetmbr, fmt.Sprintf("-Server %q", m.Server))
		}
		cmdgetmbr = append(cmdgetmbr, "; ")

		// add member
		cmdadd := []string{fmt.Sprintf("Set-ADGroup -Identity $group -Add @{ 'member' = $member.DistinguishedName }")}
		if g.Group.Server != "" {
			cmdadd = append(cmdadd, fmt.Sprintf("-Server %q", g.Group.Server))
		}
		cmdadd = append(cmdadd, "; ")
		cmd := []string{}
		cmd = append(cmdgetgrp, cmdgetmbr...)
		cmd = append(cmd, cmdadd...)

		result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
		if err != nil {
			return fmt.Errorf("while running Set-ADGroup Add: %s", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("command Set-ADGroup Add exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
		}
	}

	return nil
}

func (g *GroupMembership) Delete(client *winrm.Client, execLocally bool, server string) error {
	cmd := []string{fmt.Sprintf("Remove-ADGroupMember %q -Members (Get-ADGroupMember %q) -Confirm:$false", g.Group.GUID, g.Group.GUID)}
	if server != "" {
		cmd = append(cmd, fmt.Sprintf("-Server %q", server))
	}
	result, err := RunWinRMCommand(client, cmd, false, false, execLocally)
	if err != nil {
		return fmt.Errorf("while running Remove-ADGroupMember: %s", err)
	} else if result.ExitCode != 0 && !strings.Contains(result.StdErr, "InvalidData") {
		return fmt.Errorf("command Remove-ADGroupMember exited with a non-zero exit code(%d), stderr: %s, stdout: %s", result.ExitCode, result.StdErr, result.Stdout)
	}
	return nil
}

func NewGroupMembershipFromHost(client *winrm.Client, groupID string, execLocally bool, server string) (*GroupMembership, error) {
	result := &GroupMembership{
		Group: &Grp{
			GUID: groupID,
		},
	}

	gm, err := result.getGroupMembers(client, execLocally, server)
	if err != nil {
		return nil, err
	}
	result.GroupMembers = gm

	return result, nil
}

func NewGroupMembershipFromState(d *schema.ResourceData) (*GroupMembership, error) {
	group := d.Get("group").(*schema.Set)
	members := d.Get("group_members").(*schema.Set)

	result := &GroupMembership{
		Group:        &Grp{},
		GroupMembers: []*GroupMember{},
	}

	for _, g := range group.List() {
		if g == "" {
			continue
		}
		id := g.(map[string]interface{})["id"]
		srv := g.(map[string]interface{})["server"]
		newGroup := &Grp{
			GUID:   id.(string),
			Server: srv.(string),
		}
	}

	for _, m := range members.List() {
		if m == "" {
			continue
		}
		mbrGUID := m.(map[string]interface{})["member"]
		srv := m.(map[string]interface{})["server"]
		newMember := &GroupMember{
			GUID:   mbrGUID.(string),
			Server: srv.(string),
		}

		result.GroupMembers = append(result.GroupMembers, newMember)
	}
	return result, nil
}
