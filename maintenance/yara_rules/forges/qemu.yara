rule qemu: forge
{
    meta:
        description = "Rule for Qemu Git references"
        name = "qemu"

    strings:

        $string1 = "git.qemu.org"

    condition:
        any of ($string*)

}
