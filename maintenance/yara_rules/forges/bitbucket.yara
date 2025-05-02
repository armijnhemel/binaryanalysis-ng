rule bitbucket: forge
{
    meta:
        description = "Rule for BitBucket references"
        name = "bitbucket"

    strings:

        $string1 = "bitbucket.org"

    condition:
        any of ($string*)

}
