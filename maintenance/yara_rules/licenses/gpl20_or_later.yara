rule gpl20_or_later: license copyleft
{
    meta:
        description = "Rule for GPL2.0-or-later"
        name = "gpl20_or_later"

    strings:

        $string1 = "licensed under the GPL Version 2 or later"
        $string2 = "GNU GPL version 2 or later"
        $string3 = "GPL v2 or any later"
        $string4 = "GPL-2.0-or-later" fullword
        $string5 = "GPL-2.0+" fullword

    condition:
        any of ($string*)

}
