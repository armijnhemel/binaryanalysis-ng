CREATE TABLE IF NOT EXISTS package(sha256 text, purl text);
CREATE TABLE IF NOT EXISTS package_contents(package_sha256 text, full_name text, name text, sha256 text);

CREATE INDEX package_sha256 ON package (sha256);
CREATE INDEX package_contents_sha256 ON package_contents (sha256);
CREATE INDEX package_contents_filename ON package_contents (sha256);
