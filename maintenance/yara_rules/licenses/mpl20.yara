rule mpl20: license
{
    meta:
        description = "Rule for MPL 2.0 license"
        name = "mpl20"

    strings:

        $string1 = "mozilla.org/MPL/2.0/"
        $string2 = "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0."

    condition:
        any of ($string*)

}
