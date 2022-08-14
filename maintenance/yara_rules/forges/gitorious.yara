rule gitorious: forge
{
    meta:
        description = "Rule for Gitorious references"
        name = "gitorious"

    strings:

        $string1 = "gitorious.org"

    condition:
        any of ($string*)

}
