rule aws_key
{
    meta:
        description = "Rule for detecting AWS credentials"
        name = "AWS credentials"
        cwe = "CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:

        $aws_key = /(AKIA[0-9A-Z]{16})/

    condition:
        $aws_key

}

rule database_connection_string
{
    meta:
        description = "Rule for detecting credentials in a database connection string"
        name = "database connection string"
        cwe = "CWE-257, CWE-259, CWE-312, CWE-321, CWE-798"
        spdx_license = "Apache-2.0"

    strings:

        $connection_string = /(mysql|oracle|odbc|jdbc|postgresql|mongodb|mongo|couchbase):\/\/\w{3,}:\w{3,}(@[^\/]{3,}\/)/ nocase

    condition:
        $connection_string

}
