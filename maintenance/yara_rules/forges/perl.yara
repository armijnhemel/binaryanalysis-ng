rule perl: forge
{
    meta:
        description = "Rule for Perl Git references"
        name = "perl"

    strings:

        $string1 = "git.perl.org"

    condition:
        any of ($string*)

}
