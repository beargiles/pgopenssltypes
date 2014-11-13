pgopenssltypes Installation
===========================

Installation instructions on Ubuntu Linux.

* Build extension with 'make'
* Copy everything under sql to /usr/share/postgresql/9.3/extension
* Copy src/pgopenssltypes.so to /usr/lib/postgresql/9.3/lib
* Launch psql
* Execute 'create extension pgopenssltypes;'

Removal instructions

* Launch psql
* Execute 'drop extension pgopenssltypes;'
