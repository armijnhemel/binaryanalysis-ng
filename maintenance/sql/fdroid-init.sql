create table if not exists fdroid_application(identifier text, source text, license text, primary key(identifier));
create table if not exists fdroid_package(identifier text, version text, apkname text, sha256 text, srcpackage text, primary key(identifier, version));
create table if not exists apk_contents(apkname text, filename text, sha256 text);
