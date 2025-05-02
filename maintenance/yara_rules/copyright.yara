rule copyright
{
    meta:
        description = "Rule for copyright hints"
        name = "copyright"

    strings:

        $string1 = "copyright" nocase

    condition:
        any of ($string*)

}
