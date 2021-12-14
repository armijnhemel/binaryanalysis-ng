rule lgpl21_or_later: license
{
    meta:
        description = "Rule for LGPL2.1 or later"
        name = "lgpl21_or_later"

    strings:

        $string1 = "LGPL-2.1-or-later"
        $string2 = "LGPL-2.1+"
        $string3 = "License LGPLv2.1+: GNU Lesser GPL version 2.1 or later <https://gnu.org/licenses/lgpl.html>"
        $string4 = "Licensed under the GNU Lesser General Public License, version 2.1."

    condition:
        any of ($string*)

}
