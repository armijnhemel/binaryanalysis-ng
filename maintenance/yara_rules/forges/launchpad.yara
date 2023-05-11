rule launchpad: forge
{
    meta:
        description = "Rule for Launchpad SCM references"
        name = "launchpad"

    strings:

        $string1 = "git.launchpad.net"
        $string2 = "launchpad.net"

    condition:
        any of ($string*)

}
