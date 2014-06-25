oVirt node / RHEVH main package check
=====================================

1- Add package name need to be checked in `config.yml`, and query constraints. e.g.:

    - libvirt
    - el6_5


default query method by now is by `package`

https://errata.devel.redhat.com/package/show/libvirt

and then limit the result by column `Brew Build` inclued `el6_5`


2- Add `release_date` in `config.yml` as a compare stand

All `release_date` from the query result will compare with the the one in `config.yml`


3- Add `notifaction target` in `config.yml`
In the end, will send the report as email to the given target.