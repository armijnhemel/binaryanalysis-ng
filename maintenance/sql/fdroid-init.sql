CREATE TABLE IF NOT EXISTS fdroid_application(identifier text, source text, license text, PRIMARY KEY(identifier));
CREATE TABLE IF NOT EXISTS fdroid_package(identifier text, version text, apk text, sha256 text, source_package text, PRIMARY KEY(identifier, version));
CREATE TABLE IF NOT EXISTS apk_contents(apk text, full_name text, name text, sha256 text);
CREATE INDEX apk_contents_sha256 ON apk_contents(sha256);
CREATE INDEX apk_contents_name ON apk_contents(name);
