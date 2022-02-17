rule qt: forge
{
    meta:
        description = "Rule for Qt Git references"
        name = "qt"

    strings:

        $string1 = "code.qt.io"

    condition:
        any of ($string*)

}
