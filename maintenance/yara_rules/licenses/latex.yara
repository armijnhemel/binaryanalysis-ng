rule latex: license
{
    meta:
        description = "Rule for LaTeX license"
        name = "latex"

    strings:

        $string1 = "latex-project.org/lppl.txt"

    condition:
        any of ($string*)

}
