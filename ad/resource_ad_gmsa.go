package ad

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

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
			"container": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "A DN of the container object that will be holding the Gmsa.",
				ValidateFunc:     validation.StringMatch(regexp.MustCompile(DistNameRegexp), "Must be a valid distinguished name (case sensitive). (Example: CN=Computer1,OU=Computers,DC=contoso,DC=com)"),
				DiffSuppressFunc: suppressCaseDiff,
			},
			"display_name": {
				Type:        schema.TypeString,
				Optional:    true,
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
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "This value sets the encryption types supported flags of the Active Directory.",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice([]string{"RC4", "AES128", "AES256"}, false),
				},
				MinItems: 1,
			},
			"managed_password_interval_in_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     30,
				Description: "Specifies the number of days for the password change interval.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Specifies the name of the Gmsa object.",
			},
			"principals_allowed_to_delegate_to_account": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "This value sets principals allowed to delegate. (Must be a distinguished name)",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringMatch(regexp.MustCompile(DistNameRegexp), "Must be a valid distinguished name (case sensitive). (Example: CN=Computer1,OU=Computers,DC=contoso,DC=com)"),
				},
				MinItems: 1,
			},
			"principals_allowed_to_retrieve_managed_password": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "This value sets principals allowed to retrieve gmsa password. (Must be a distinguished name)",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringMatch(regexp.MustCompile(DistNameRegexp), "Must be a valid distinguished name (case sensitive). (Example: CN=Computer1,OU=Computers,DC=contoso,DC=com)"),
				},
				MinItems: 1,
			},
			"sam_account_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The pre-win2k Gmsa logon name.",
			},
			"service_principal_names": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "This value sets SPN's for the gmsa.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"trusted_for_delegation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "If set to true, the Gmsa account is trusted for Kerberos delegation. A service that runs under an account that is trusted for Kerberos delegation can assume the identity of a client requesting the service. This parameter sets the TrustedForDelegation property of an account object.",
			},
			"guid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The GUID of the gmsa object.",
			},
			"sid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The SID of the gmsa object.",
			},
		},
	}
}

func resourceADGmsaCreate(d *schema.ResourceData, meta interface{}) error {
	g, err := winrmhelper.GetGmsaFromResource(d)
	if err != nil {
		return err
	}

	guid, err := g.NewGmsa(meta.(*config.ProviderConf))
	if err != nil {
		return err
	}

	d.SetId(guid)

	return resourceADGmsaRead(d, meta)
}

func resourceADGmsaRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("Reading ad_gmsa resource for user with guid: %q", d.Id())
	g, err := winrmhelper.GetGmsaFromHost(meta.(*config.ProviderConf), d.Id())
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
	_ = d.Set("container", g.Container)
	_ = d.Set("display_name", g.DisplayName)
	_ = d.Set("delegated", g.Delegated)
	_ = d.Set("description", g.Description)
	_ = d.Set("dns_host_name", g.DNSHostName)
	_ = d.Set("enabled", g.Enabled)
	_ = d.Set("expiration", g.Expiration)
	_ = d.Set("guid", g.GUID)
	_ = d.Set("home_page", g.HomePage)
	_ = d.Set("kerberos_encryption_type", g.KerberosEncryptionType)
	_ = d.Set("managed_password_interval_in_days", g.ManagedPasswordIntervalInDays)
	_ = d.Set("name", g.Name)
	_ = d.Set("principals_allowed_to_delegate_to_account", g.PrincipalsAllowedToDelegateToAccount)
	_ = d.Set("principals_allowed_to_retrieve_managed_password", g.PrincipalsAllowedToRetrieveManagedPassword)
	_ = d.Set("sam_account_name", g.SAMAccountName)
	_ = d.Set("service_principal_names", g.ServicePrincipalNames)
	_ = d.Set("trusted_for_delegation", g.TrustedForDelegation)
	_ = d.Set("sid", g.SID.Value)

	return nil
}

func resourceADGmsaUpdate(d *schema.ResourceData, meta interface{}) error {
	g, err := winrmhelper.GetGmsaFromResource(d)
	if err != nil {
		return err
	}

	err = g.ModifyGmsa(d, meta.(*config.ProviderConf))
	if err != nil {
		return err
	}
	return resourceADGmsaRead(d, meta)
}

func resourceADGmsaDelete(d *schema.ResourceData, meta interface{}) error {
	g, err := winrmhelper.GetGmsaFromHost(meta.(*config.ProviderConf), d.Id())
	if err != nil {
		if strings.Contains(err.Error(), "ADIdentityNotFoundException") {
			return nil
		}
		return fmt.Errorf("while retrieving Gmsa data from host: %s", err)
	}
	err = g.DeleteGmsa(meta.(*config.ProviderConf))
	if err != nil {
		return fmt.Errorf("while deleting Gmsa: %s", err)
	}
	return nil
}
