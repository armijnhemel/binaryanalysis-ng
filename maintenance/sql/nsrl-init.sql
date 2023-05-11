create table if not exists nsrl_hash(sha1 text, md5 text, crc32 text, filename text, primary key(sha1));
create table if not exists nsrl_entry(sha1 text, product_code int);
create table if not exists nsrl_manufacturer(code int, name text, primary key(code));
create table if not exists nsrl_os(code int, name text, version text, manufacturer_code int, primary key(code));
create table if not exists nsrl_product(code int, name text, version text, manufacturer_code int, application_type text, primary key(code));
