package ad

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccDataSourceADGmsa_basic(t *testing.T) {
	envVars := []string{
		"TF_VAR_ad_gmsa_name",
		"TF_VAR_ad_gmsa_sam",
		"TF_VAR_ad_gmsa_display_name",
		"TF_VAR_ad_gmsa_desc",
		"TF_VAR_ad_user_container",
	}
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t, envVars) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceADGmsaBasic(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.ad_gmsa.d", "id",
						"ad_gmsa.a", "id",
					),
				),
			},
		},
	})
}

func testAccDataSourceADGmsaBasic() string {
	return `
	variable "ad_gmsa_name" {}
	variable "ad_gmsa_sam" {}
	variable "ad_gmsa_display_name" {}
	variable "ad_gmsa_desc" {}
	variable "ad_gmsa_container" {}

	resource "ad_gmsa" "a" {
		name = var.ad_gmsa_name
		dns_host_name = var.ad_gmsa_name
		sam_account_name = var.ad_gmsa_sam
		display_name = var.ad_gmsa_display_name
		container = var.ad_gmsa_container
	}
	 
	 data "ad_gmsa" "d" {
	    gmsa_id = ad_gmsa.a.id
	 }
`
}
