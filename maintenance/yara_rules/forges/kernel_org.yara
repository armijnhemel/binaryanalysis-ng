rule kernel_org: forge
{
    meta:
        description = "Rule for Kernel.org Git references"
        name = "kernel_org"

    strings:

        $string1 = "git.kernel.org"

    condition:
        any of ($string*)

}
