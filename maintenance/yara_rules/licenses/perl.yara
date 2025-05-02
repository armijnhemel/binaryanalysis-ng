rule perl: license
{
    meta:
        description = "Rule for Perl license"
        name = "perl"

    strings:

        $string1 = "dev.perl.org/licenses/"

    condition:
        any of ($string*)

}
