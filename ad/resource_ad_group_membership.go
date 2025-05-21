package ad

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceADGroupMembership() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_group_membership` manages the members of a given Active Directory group.",
		Create:      resourceADGroupMembershipCreate,
		Read:        resourceADGroupMembershipRead,
		Update:      resourceADGroupMembershipUpdate,
		Delete:      resourceADGroupMembershipDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"group": {
				Type:     schema.TypeSet,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The identifier of the group (GUID, SID, DN, or SAM Account Name).",
						},
						"domain": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The domain where the group resides.",
						},
						"user": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Username used for authentication (optional override).",
						},
						"password": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Password for the user (optional override).",
						},
					},
				},
				Description: "Block containing group identifier and optional connection overrides.",
			},
			"members": {
				Type:     schema.TypeSet,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeList,
							Required:    true,
							Elem:        &schema.Schema{Type: schema.TypeString},
							Description: "A list of member identifiers (GUID, SID, DN, or SAM Account Name).",
						},
						"domain": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "The domain for the member objects.",
						},
						"user": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "Username for member-level authentication (optional).",
						},
						"password": {
							Type:        schema.TypeString,
							Optional:    true,
							Sensitive:   true,
							Description: "Password for member-level authentication (optional).",
						},
					},
				},
				Description: "Block containing list of members and optional authentication overrides.",
			},
		},
	}
}

func resourceADGroupMembershipRead(d *schema.ResourceData, meta interface{}) error {
	toks := strings.Split(d.Id(), "_")

	gm, err := winrmhelper.NewGroupMembershipFromHost(meta.(*config.ProviderConf), toks[0])
	if err != nil {
		return err
	}
	memberList := make([]string, len(gm.Members))

	for idx, m := range gm.Members {
		memberList[idx] = m.ID
	}
	_ = d.Set("members", memberList)
	_ = d.Set("group", toks[0])
	return nil
}

func resourceADGroupMembershipCreate(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Create(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	membershipUUID, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("while generating UUID to use as unique membership ID: %s", err)
	}

	id := fmt.Sprintf("%s_%s", gm.Group.GUID, membershipUUID)
	d.SetId(id)

	return nil
}

func resourceADGroupMembershipUpdate(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Update(meta.(*config.ProviderConf), gm.Members)
	if err != nil {
		return err
	}

	return resourceADGroupMembershipRead(d, meta)
}

func resourceADGroupMembershipDelete(d *schema.ResourceData, meta interface{}) error {
	gm, err := winrmhelper.NewGroupMembershipFromState(d)
	if err != nil {
		return err
	}

	err = gm.Delete(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}
