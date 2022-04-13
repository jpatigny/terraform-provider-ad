variable name1     { default = "testGmsa" }

variable name2     { default = "testGmsa2" }
variable container { default = "CN=Gmsas,DC=contoso,DC=com" }

resource "ad_gmsa" "g1" {
  name             = var.name1
  dns_host_name    = var.name1
  sam_account_name = format("%s$", var.name1)
}

data "ad_computer" "c" {
  dn = "cn=test123,cn=Computers,dc=contoso,dc=com"
}

resource "ad_gmsa" "g" {
  name                                            = var.name
  sam_account_name                                = format("%s$", var.name)
  dns_host_name                                   = var.name 
  container                                       = var.container
  display_name                                    = var.name
  description	                                  = "Some desc 2"
  delegated                                       = false
  managed_password_interval_in_days               = 15
  kerberos_encryption_type                        = [ "AES128","AES256" ]
  expiration                                      = "2021-12-30T00:00:00+00:00"
  service_principal_names                         = [
    "HTTP/Machine3.corp.contoso.com",
    "WSMAN/Machine3.corp.contoso.com"
  ]
  principals_allowed_to_delegate_to_account       = [
    "CN=group1,DC=groups,DC=contoso,DC=com",
    data.ad_computer.c.dn
  ]
  principals_allowed_to_retrieve_managed_password = [
    "CN=group2,DC=groups,DC=contoso,DC=com",
    "CN=computer2,DC=computers,DC=contoso,DC=com"
  ]
}