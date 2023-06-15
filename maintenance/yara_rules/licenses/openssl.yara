rule openssl: license
{
    meta:
        description = "Rule for OpenSSL license"
        name = "openssl"

    strings:

        $string1 = "www.openssl.org/source/license.html"

    condition:
        any of ($string*)

}
