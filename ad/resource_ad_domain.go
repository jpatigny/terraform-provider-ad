package ad

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceADDomain() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_group` manages Group objects in an Active Directory tree.",
		Create:      resourceADDomainCreate,
		Read:        resourceADDomainRead,
		Update:      resourceADDomainUpdate,
		Delete:      resourceADDomainDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The domain name.",
			},
			"allowed_dns_suffixes": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "The list of allowed dns suffixes for the domain.",
				MinItems:    1,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceADDomainCreate(d *schema.ResourceData, meta interface{}) error {
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()

	u, err := winrmhelper.GetDomainFromResource(d)
	if err != nil {
		return err
	}

	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	guid, err := u.AddDomain(client, isLocal)
	if err != nil {
		return err
	}
	d.SetId(guid)
	return resourceADDomainRead(d, meta)
}

func resourceADDomainRead(d *schema.ResourceData, meta interface{}) error {
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()
	log.Printf("Reading AD_Domain resource for domain with GUID: %q", d.Id())
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	g, err := winrmhelper.GetDomainFromHost(client, d.Id(), isLocal)
	if err != nil {
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			d.SetId("")
			return nil
		}
		return err
	}
	if g == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("domain", g.Domain)
	_ = d.Set("allowed_dns_suffixes", g.AllowedDNSSuffixes)
	return nil
}

func resourceADDomainUpdate(d *schema.ResourceData, meta interface{}) error {
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()

	g, err := winrmhelper.GetDomainFromResource(d)
	if err != nil {
		return err
	}

	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	err = g.ModifyDomain(d, client, isLocal)
	if err != nil {
		return err
	}
	return resourceADDomainRead(d, meta)
}

func resourceADDomainDelete(d *schema.ResourceData, meta interface{}) error {
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()
	conn, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(conn)

	g, err := winrmhelper.GetDomainFromHost(conn, d.Id(), isLocal)
	if err != nil {
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return err
	}
	err = g.DeleteDomain(conn, isLocal)
	if err != nil {
		return fmt.Errorf("while deleting group: %s", err)
	}
	return nil
}
