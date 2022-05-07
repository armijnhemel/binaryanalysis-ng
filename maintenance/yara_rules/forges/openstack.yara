rule openstack: forge
{
    meta:
        description = "Rule for OpenStack Git references"
        name = "openstack"

    strings:

        $string1 = "git.openstack.org"

    condition:
        any of ($string*)

}
