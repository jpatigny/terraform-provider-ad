package msad

import (
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-msad/msad/internal/ldaphelper"
)

func resourceMSADUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceMSADUserCreate,
		Read:   resourceMSADUserRead,
		Update: resourceMSADUserUpdate,
		Delete: resourceMSADUserDelete,

		Schema: map[string]*schema.Schema{
			"domain_dn": {
				Type:     schema.TypeString,
				Required: true,
			},
			"display_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"principal_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"sam_account_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"initial_password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"change_at_next_login": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
	}
}

func resourceMSADUserCreate(d *schema.ResourceData, meta interface{}) error {
	u := ldaphelper.GetUserFromResource(d)
	conn := meta.(ProviderConf).LDAPConn
	dn, err := u.AddUser(conn)
	if err != nil {
		return err
	}
	d.SetId(*dn)
	return resourceMSADUserRead(d, meta)
}

func resourceMSADUserRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("Reading msad_user resource for DN: %q", d.Id())
	conn := meta.(ProviderConf).LDAPConn
	domainDN := d.Get("domain_dn").(string)
	u, err := ldaphelper.GetUserFromLDAP(conn, d.Id(), domainDN)
	if err != nil {
		if strings.Contains(err.Error(), "No entries found for filter") {
			d.SetId("")
			return nil
		}
		return err
	}
	if u == nil {
		d.SetId("")
		return nil
	}
	d.Set("sam_account_name", u.SAMAccountName)
	d.Set("display_name", u.DisplayName)
	d.Set("principal_name", u.PrincipalName)
	d.Set("change_at_next_login", u.ChangeAtLogin)

	return nil
}

func resourceMSADUserUpdate(d *schema.ResourceData, meta interface{}) error {
	u := ldaphelper.GetUserFromResource(d)
	conn := meta.(ProviderConf).LDAPConn
	err := u.ModifyUser(d, conn)
	if err != nil {
		return err
	}
	return resourceMSADUserRead(d, meta)
}

func resourceMSADUserDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(ProviderConf).LDAPConn
	delReq := ldap.NewDelRequest(d.Id(), []ldap.Control{})
	delReq.DN = d.Id()
	err := conn.Del(delReq)
	if err != nil {
		return err
	}
	return resourceMSADUserRead(d, meta)
}
