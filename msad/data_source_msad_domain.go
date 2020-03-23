package msad

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-provider-msad/msad/internal/ldaphelper"
)

func dataSourceMSADDomain() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceMSADDomainRead,

		Schema: map[string]*schema.Schema{
			"netbios_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"domain_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"domain_dn": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func dataSourceMSADDomainRead(d *schema.ResourceData, meta interface{}) error {
	nb := d.Get("netbios_name").(string)
	dns := d.Get("domain_name").(string)
	dn := d.Get("domain_dn").(string)

	dseConn := meta.(ProviderConf).LDAPDSEConn
	domain, err := ldaphelper.GetDomainFromLDAP(dseConn, dn, nb, dns)
	if err != nil {
		return err
	}

	d.Set("netbios_name", domain.NetbiosName)
	d.Set("domain_name", domain.DomainName)
	d.Set("domain_dn", domain.DN)
	d.SetId(domain.DN)

	return nil
}
