rule centos: forge
{
    meta:
        description = "Rule for CentOS Git references"
        name = "centos"

    strings:

        $string1 = "git.centos.org"

    condition:
        any of ($string*)

}
