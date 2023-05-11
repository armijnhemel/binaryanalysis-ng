rule gitlab: forge
{
    meta:
        description = "Rule for GitLab references"
        name = "gitlab"

    strings:

        $string1 = "gitlab.com"
        $string2 = "gitlab.io"

    condition:
        any of ($string*)

}
