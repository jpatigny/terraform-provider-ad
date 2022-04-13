data "ad_gmsa" "g" {
    gmsa_id = "testGmsa$"
}

output "g1_sam" {
    value = data.ad_gmsa.g.sam_account_name
}

output "g1_trusted_for_delegation" {
    value = data.ad_gmsa.g.trusted_for_delegation
}

output "g1_all" {
    value = data.ad_gmsa.g
}

data "ad_gmsa" "g2" {
    gmsa_id = "CN=testGmsa,OU=gmsas,DC=contoso,DC=com"
}

output "g2_guid" {
    value = data.ad_gmsa.g2.id
}