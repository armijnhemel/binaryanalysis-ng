rule apache: forge
{
    meta:
        description = "Rule for Apache SCM references"
        name = "apache"

    strings:

        $string1 = "svn.apache.org"

    condition:
        any of ($string*)

}
