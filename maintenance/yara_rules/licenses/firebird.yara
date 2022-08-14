rule firebird: license
{
    meta:
        description = "Rule for Firebird license"
        name = "firebird"

    strings:

        $string1 = "firebirdsql.org/en/licensing/"

    condition:
        any of ($string*)

}
