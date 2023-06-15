# Configuration of the Elasticsearch reporter in BANG

NOTE: ElasticSearch support was removed from BANG. Below you can only find
some historical information which will be removed in the near future.

BANG can write its results to Elasticsearch and make it available for further
investigation and processing using standard Elasticsearch tools.

Note: these are mostly personal notes for installation and configuration of
Amazon's "Open Distro for Elasticsearch" on Fedora 30.

## Configuring Elasticsearch

In this document it is assumed that Amazon's "Open Distro for Elasticsearch"
( https://opendistro.github.io/for-elasticsearch/ ) is used. The version
described is 7.0.1.

For now it should be run without SSL, so you need to change settings in:

    /etc/elasticsearch/elasticsearch.yml

and replace:

    opendistro_security.ssl.http.enabled: true

with:

    opendistro_security.ssl.http.enabled: false

and restart Elasticsearch

Please note that this *will* be changed in the future.

## Install Kibana

Install opendistroforelasticsearch-kibana

Then edit:

    /etc/kibana/kibana.yml

and change:

    elasticsearch.url: https://localhost:9200

into:

    elasticsearch.hosts: http://localhost:9200

(note the change from https to http!)

and start Kibana.

### Creating a user

Users can be added in Kibana. Log into kibana and create a user. Please note:
user names are case sensitive!

Also, "Open Distro for Elasticsearch" doesn't like passwords shorter than
5 characters. In the rest of the document it is assumed that the user is
'bang' and the password is 'bangbang'.

The index that will be used for Elasticsearch is 'bang'.

## Installing Elasticsearch Python bindings

Install:

    python3-elasticsearch

# Configure BANG to use Elasticsearch

The file bang.config has a section 'elasticsearch'. In these the following
should be changed:

    elastic_enabled = no

should be changed to:

    elastic_enabled = yes
