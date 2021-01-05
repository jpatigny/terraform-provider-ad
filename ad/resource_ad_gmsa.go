package ad

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

// DistNameRegexp matched regex to validate a distinguished name
const DistNameRegexp = `^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$`

func resourceADGmsa() *schema.Resource {
	return &schema.Resource{
		Description: "`ad_gmsa` manages Gmsa objects in an Active Directory tree.",
		Create:      resourceADGmsaCreate,
		Read:        resourceADGmsaRead,
		Update:      resourceADGmsaUpdate,
		Delete:      resourceADGmsaDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Schema: map[string]*schema.Schema{
			"compound_identity_supported": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Indicates whether an account supports Kerberos service tickets which includes the authorization data for the user's device.",
			},
			"container": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "A DN of the container object that will be holding the Gmsa.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(DistNameRegexp), "Must be a valid distinguished name."),
				DiffSuppressFunc: suppressCaseDiff,
			},
			"display_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The Display Name of an Active Directory Gmsa.",
			},
			"delegated": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If set to false, the Gmsa will not be delegated to a service.",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies a description of the object. This parameter sets the value of the Description property for the Gmsa object.",
			},
			"dns_host_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the dns host name of the Gmsa object.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "If set to false, the Gmsa will be disabled.",
			},
			"expiration": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "expiration date of the gmsa.",
				ValidateFunc: validation.IsRFC3339Time,
			},
			"home_page": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the URL of the home page of the object. This parameter sets the homePage property of a Gmsa object.",
			},
			"kerberos_encryption_type": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "This value sets the encryption types supported flags of the Active Directory.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{
						"des",
						"rc4",
						"aes128",
						"aes256",
					}, false),
				},
			},
			"managed_password_interval_in_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     0,
				Description: "Specifies the number of days for the password change interval.",
			},
			"principals_allowed_to_delegate_to_account": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "This value sets the encryption types supported flags of the Active Directory.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"principals_allowed_to_retrieve_managed_password": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "This value sets the encryption types supported flags of the Active Directory.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"sam_account_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The pre-win2k Gmsa logon name.",
			},
			"trusted_for_delegation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, the Gmsa account is trusted for Kerberos delegation. A service that runs under an account that is trusted for Kerberos delegation can assume the identity of a client requesting the service. This parameter sets the TrustedForDelegation property of an account object.",
			},
		},
	}
}

func resourceADGmsaCreate(d *schema.ResourceData, meta interface{}) error {
	//g := winrmhelper.GetGmsaFromResource(d)
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	// import ps replication functions
	err = winrmhelper.GetRepCmdlet(client)
	if err != nil {
		winrmhelper.ImportRepCmdlet(client)
	}

	// create gmsa
	// guid, err := g.NewGmsa(client)
	// if err != nil {
	// 	return err
	// }

	// d.SetId(guid)
	return resourceADGmsaRead(d, meta)
}

func resourceADGmsaRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("Reading ad_Gmsa resource for Gmsa with guid: %q", d.Id())
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	g, err := winrmhelper.GetGmsaFromHost(client, d.Id())
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
	_ = d.Set("compound_identity_supported", g.CompoundIdentitySupported)
	_ = d.Set("container", g.Container)
	_ = d.Set("display_name", g.DisplayName)
	_ = d.Set("delegated", g.Delegated)
	_ = d.Set("description", g.Description)
	_ = d.Set("dns_host_name", g.DNSHostName)
	_ = d.Set("enabled", g.Enabled)
	_ = d.Set("expiration", g.Expiration)
	_ = d.Set("home_page", g.HomePage)
	_ = d.Set("kerberos_encryption_type", g.KerberosEncryptionType)
	_ = d.Set("principals_allowed_to_delegate_to_account", g.PrincipalsAllowedToDelegateToAccount)
	_ = d.Set("principals_allowed_to_retrieve_managed_password", g.PrincipalsAllowedToRetrieveManagedPassword)
	_ = d.Set("sam_account_name", g.SAMAccountName)
	_ = d.Set("trusted_for_delegation", g.TrustedForDelegation)

	return nil
}

func resourceADGmsaUpdate(d *schema.ResourceData, meta interface{}) error {
	g := winrmhelper.GetGmsaFromResource(d)
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	// import ps replication functions
	// err = winrmhelper.GetRepCmdlet(client)
	// if err != nil {
	// 	winrmhelper.ImportRepCmdlet(client)
	// }

	err = g.ModifyGmsa(d, client)
	if err != nil {
		return err
	}
	return resourceADGmsaRead(d, meta)
}

func resourceADGmsaDelete(d *schema.ResourceData, meta interface{}) error {
	client, err := meta.(ProviderConf).AcquireWinRMClient()
	if err != nil {
		return err
	}
	defer meta.(ProviderConf).ReleaseWinRMClient(client)

	// import ps replication functions
	// err = winrmhelper.GetRepCmdlet(client)
	// if err != nil {
	// 	winrmhelper.ImportRepCmdlet(client)
	// }

	g, err := winrmhelper.GetGmsaFromHost(client, d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return fmt.Errorf("while retrieving Gmsa data from host: %s", err)
	}
	err = g.DeleteGmsa(client)
	if err != nil {
		return fmt.Errorf("while deleting Gmsa: %s", err)
	}
	return resourceADGmsaRead(d, meta)
}
