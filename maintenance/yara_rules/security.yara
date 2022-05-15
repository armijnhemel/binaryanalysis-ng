rule aws_key
{
    meta:
        description = "Detect AWS credentials"
        name = "AWS credentials"
        cwe = "CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:
        $aws_key = /(AKIA[0-9A-Z]{16})/

    condition:
        $aws_key

}

rule aws_secret_access_key
{
    meta:
        description = "Detect AWS secret access keys"
        name = "AWS secret access key"
        cwe = "CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:
        $aws_key = /AWS Secret Access Key [^:]*:[ \t]*([^\s]+)/ nocase

    condition:
        $aws_key

}

rule database_connection_string
{
    meta:
        description = "Detect credentials in a database connection string"
        name = "database connection string"
        cwe = "CWE-257, CWE-259, CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:
        $connection_string = /(mysql|oracle|odbc|jdbc|postgresql|mongodb|mongo|couchbase):\/\/\w{3,}:\w{3,}(@[^\/]{3,}\/)/ nocase

    condition:
        $connection_string

}

rule npm_registry
{
    meta:
        description = "Detect NPM registry auth tokens"
        name = "NP auth token"
        cwe = "CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:
        $npm = /(\/\/registry\.npmjs\.org\/:_authToken=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/ nocase

    condition:
        $npm

}
rule slack_token
{
    meta:
        description = "Detect Slack tokens"
        name = "Slack token"
        cwe = "CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:
        $slack = /xox[sp]-[0-9]{10}-[0-9]{10}-[0-9]{12}-[a-z0-9]{32}/ nocase

    condition:
        $slack

}
