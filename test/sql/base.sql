\set ECHO 0
BEGIN;
\i sql/pgopenssltypes.sql
\set ECHO all

-- You should write your tests

--SELECT pgx509('test');

ROLLBACK;
