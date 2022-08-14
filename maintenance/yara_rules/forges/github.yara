rule github: forge
{
    meta:
        description = "Rule for GitHub references"
        name = "github"

    strings:

        $string1 = "github.com"
        $string2 = "github.io"
        $string3 = "raw.githubusercontent.com"

    condition:
        any of ($string*)

}
