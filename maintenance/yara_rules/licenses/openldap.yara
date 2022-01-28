rule openldap: license
{
    meta:
        description = "Rule for OpenLDAP license"
        name = "openldap"

    strings:

        $string1 = "www.OpenLDAP.org/license.html"

    condition:
        any of ($string*)

}
