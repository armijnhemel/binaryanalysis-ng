rule sourceware: forge
{
    meta:
        description = "Rule for Sourceware SCM references"
        name = "sourceware"

    strings:

        $string1 = "sourceware.org/git/"

    condition:
        any of ($string*)

}
