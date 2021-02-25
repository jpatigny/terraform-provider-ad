package ad

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func resourceADDNSSuffix() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_group` manages Group objects in an Active Directory tree.",
		Create:      resourceADDNSSuffixCreate,
		Read:        resourceADDNSSuffixRead,
		Delete:      resourceADDNSSuffixDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The domain name.",
			},
			"allowed_dns_suffix": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Allowed DNS Suffix.",
			},
		},
	}
}

func resourceADDNSSuffixCreate(d *schema.ResourceData, meta interface{}) error {
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()

	u, err := winrmhelper.GetDNSSuffixFromResource(d)
	if err != nil {
		return err
	}

	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	suf, err := u.AddDNSSuffix(client, isLocal)
	if err != nil {
		return err
	}
	d.SetId(suf)
	return resourceADDNSSuffixRead(d, meta)
}

func resourceADDNSSuffixRead(d *schema.ResourceData, meta interface{}) error {
	dom := d.Get("domain").(string)
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()
	log.Printf("Reading AD_DNSSuffix resource for domain with GUID: %q", d.Id())
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	g, err := winrmhelper.GetDNSSuffixFromHost(client, dom, d.Id(), isLocal)
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
	_ = d.Set("allowed_dns_suffix", g.AllowedDNSSuffixes)
	return nil
}

func resourceADDNSSuffixDelete(d *schema.ResourceData, meta interface{}) error {
	dom := d.Get("domain").(string)
	isLocal := meta.(ProviderConf).isConnectionTypeLocal()
	conn, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(conn)

	g, err := winrmhelper.GetDNSSuffixFromHost(conn, dom, d.Id(), isLocal)
	if err != nil {
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return err
	}
	err = g.DeleteDNSSuffix(conn, isLocal)
	if err != nil {
		return fmt.Errorf("while deleting group: %s", err)
	}
	return nil
}
