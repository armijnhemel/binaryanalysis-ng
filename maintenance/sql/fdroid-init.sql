CREATE TABLE IF NOT EXISTS fdroid_application(identifier text, source text, license text, PRIMARY KEY(identifier));
CREATE TABLE IF NOT EXISTS fdroid_package(identifier text, version text, apkname text, sha256 text, srcpackage text, PRIMARY KEY(identifier, version));
CREATE TABLE IF NOT EXISTS apk_contents(apkname text, filename text, sha256 text);
CREATE INDEX apk_contents_sha256 ON apk_contents USING HASH (sha256);
