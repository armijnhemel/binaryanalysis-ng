rule imagemagick: license
{
    meta:
        description = "Rule for ImageMagick license"
        name = "imagemagick"

    strings:

        $string1 = "www.imagemagick.org/script/license.php"

    condition:
        any of ($string*)

}
