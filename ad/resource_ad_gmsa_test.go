package ad

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-provider-ad/ad/internal/config"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-ad/ad/internal/winrmhelper"
)

func TestAccResourceADGmsa_basic(t *testing.T) {
	envVars := []string{
		"TF_VAR_ad_gmsa_display_name",
		"TF_VAR_ad_gmsa_sam",
		"TF_VAR_ad_gmsa_password",
		"TF_VAR_ad_gmsa_principal_name",
		"TF_VAR_ad_gmsa_container",
	}

	username := os.Getenv("TF_VAR_ad_gmsa_sam")
	resourceName := "ad_gmsa.a"

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t, envVars) },
		Providers: testAccProviders,
		CheckDestroy: resource.ComposeTestCheckFunc(
			testAccResourceADGmsaExists(resourceName, username, false),
		),
		Steps: []resource.TestStep{
			{
				Config: testAccResourceADGmsaConfigBasic(""),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaExists(resourceName, username, true),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"initial_password"},
			},
			{
				Config: testAccResourceADGmsaConfigAttributes(),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaExists(resourceName, username, true),
				),
			},
			{
				Config: testAccResourceADGmsaConfigBasic(""),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaExists(resourceName, username, true),
				),
			},
		},
	})
}

func TestAccResourceADGmsa_modify(t *testing.T) {
	envVars := []string{
		"TF_VAR_ad_gmsa_display_name",
		"TF_VAR_ad_gmsa_sam",
		"TF_VAR_ad_gmsa_name",
		"TF_VAR_ad_gmsa_container",
		"TF_VAR_ad_ou_name",
		"TF_VAR_ad_ou_description",
		"TF_VAR_ad_ou_path",
		"TF_VAR_ad_ou_protected",
	}

	username := os.Getenv("TF_VAR_ad_gmsa_sam")
	usernameSuffix := "renamed"
	renamedUsername := fmt.Sprintf("%s%s", username, usernameSuffix)
	resourceName := "ad_gmsa.a"
	expectedContainerDN := fmt.Sprintf("%s,%s", os.Getenv("TF_VAR_ad_ou_name"),
		os.Getenv("TF_VAR_ad_ou_path"))

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t, envVars) },
		Providers: testAccProviders,
		CheckDestroy: resource.ComposeTestCheckFunc(
			testAccResourceADGmsaExists(resourceName, renamedUsername, false),
		),
		Steps: []resource.TestStep{
			{
				Config: testAccResourceADGmsaConfigBasic(""),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaExists(resourceName, username, true),
				),
			},
			{
				Config: testAccResourceADGmsaConfigBasic(usernameSuffix),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaExists(resourceName, renamedUsername, true),
				),
			},
			{
				Config: testAccResourceADGmsaConfigMoved(usernameSuffix),
				Check: resource.ComposeTestCheckFunc(
					testAccResourceADGmsaContainer(resourceName, expectedContainerDN),
				),
			},
		},
	})
}

func defaultVariablesSectionGmsa() string {
	return `
	variable "ad_gmsa_principal_name"  {}
	variable "ad_gmsa_password" {}
	variable "ad_gmsa_sam" {}
	variable "ad_gmsa_display_name" {}
	`
}

func defaultGmsaSection(usernameSuffix, container string) string {
	return fmt.Sprintf(`
	principal_name = var.ad_gmsa_principal_name
	sam_account_name = "${var.ad_gmsa_sam}%s"
	initial_password = var.ad_gmsa_password
	display_name = var.ad_gmsa_display_name
	container = %s
	`, usernameSuffix, container)
}

func testAccResourceADGmsaConfigBasic(usernameSuffix string) string {
	return fmt.Sprintf(`%s
	resource "ad_gmsa" "a" {%s
 	}`, defaultVariablesSectionGmsa(), defaultGmsaSection(usernameSuffix, fmt.Sprintf("%q",
		os.Getenv("TF_VAR_ad_gmsa_container"))))

}

func testAccResourceADGmsaConfigAttributes() string {
	return fmt.Sprintf(`%s
	resource "ad_gmsa" "a" {%s
	  city                      = "City"
	  company                   = "Company"
	  country                   = "us"
	  department                = "Department"
	  description               = "Description"
	  division                  = "Division"
	  email_address             = "some@email.com"
	  employee_id               = "id"
	  employee_number           = "number"
	  fax                       = "Fax"
	  given_name                = "GivenName"
	  home_directory            = "HomeDirectory"
	  home_drive                = "HomeDrive"
	  home_phone                = "HomePhone"
	  home_page                 = "HomePage"
	  initials                  = "Initia"
	  mobile_phone              = "MobilePhone"
	  office                    = "Office"
	  office_phone              = "OfficePhone"
	  organization              = "Organization"
	  other_name                = "OtherName"
	  po_box                    = "POBox"
	  postal_code               = "PostalCode"
	  state                     = "State"
	  street_address            = "StreetAddress"
	  surname                   = "Surname"
	  title                     = "Title"
	  smart_card_logon_required = false
	  trusted_for_delegation    = true
	}`, defaultVariablesSectionGmsa(), defaultGmsaSection("", fmt.Sprintf("%q",
		os.Getenv("TF_VAR_ad_gmsa_container"))))

}

func testAccResourceADGmsaConfigCustomAttributes(customAttributes string) string {
	return fmt.Sprintf(`%s
	resource "ad_gmsa" "a" {%s
		custom_attributes = jsonencode(%s)
 	}`,
		defaultVariablesSectionGmsa(),
		defaultGmsaSection("", fmt.Sprintf("%q", os.Getenv("TF_VAR_ad_gmsa_container"))),
		customAttributes)
}

func testAccResourceADGmsaConfigMoved(usernameSuffix string) string {
	return fmt.Sprintf(`%s
	variable ad_ou_name {}
	variable ad_ou_path {}
	variable ad_ou_description {}
	variable ad_ou_protected {}
	
	resource "ad_ou" "o" { 
		name = var.ad_ou_name
		path = var.ad_ou_path
		description = var.ad_ou_description
		protected = var.ad_ou_protected
	}

	resource "ad_gmsa" "a" {%s
 	}`, defaultVariablesSectionGmsa(), defaultGmsaSection(usernameSuffix, "ad_ou.o.dn"))

}

func retrieveADGmsaFromRunningState(name string, s *terraform.State, attributeList []string) (*winrmhelper.User, error) {
	rs, ok := s.RootModule().Resources[name]
	if !ok {
		return nil, fmt.Errorf("%s key not found in state", name)
	}
	u, err := winrmhelper.GetUserFromHost(testAccProvider.Meta().(*config.ProviderConf), rs.Primary.ID, attributeList)

	return u, err

}

func testAccResourceADGmsaContainer(name, expectedContainer string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		u, err := retrieveADGmsaFromRunningState(name, s, nil)
		if err != nil {
			return err
		}

		if strings.EqualFold(u.Container, expectedContainer) {
			return fmt.Errorf("user container mismatch: expected %q found %q", u.Container, expectedContainer)
		}
		return nil
	}
}

func testAccResourceADGmsaExists(name, username string, expected bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		u, err := retrieveADGmsaFromRunningState(name, s, nil)
		if err != nil {
			if strings.Contains(err.Error(), "ADIdentityNotFoundException") && !expected {
				return nil
			}
			return err
		}

		if u.SAMAccountName != username {
			return fmt.Errorf("username from LDAP does not match expected username, %s != %s", u.SAMAccountName, username)
		}
		return nil
	}
}
