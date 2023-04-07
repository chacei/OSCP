----
-- phpLiteAdmin database dump (http://phpliteadmin.googlecode.com)
-- phpLiteAdmin version: 1.9.3
-- Exported on Apr 6th, 2023, 11:44:35PM
-- Database file: /usr/local/databases/users
----
BEGIN TRANSACTION;

----
-- Table structure for creds
----
CREATE TABLE 'creds' ('Name' TEXT, 'Password' TEXT);

----
-- Data dump for creds, a total of 5 rows
----
INSERT INTO "creds" ("Name","Password") VALUES ('aaron','5978a63b4654c73c60fa24f836386d87');
INSERT INTO "creds" ("Name","Password") VALUES ('accasia','a1420fc5ab116437368889400c4bb8e1');
INSERT INTO "creds" ("Name","Password") VALUES ('bethanyjoy02','6c0f3fde58158e4c1f4cedb29c7ef4c1');
INSERT INTO "creds" ("Name","Password") VALUES ('deanna','f463f63616cb3f1e81ce46b39f882fd5');
INSERT INTO "creds" ("Name","Password") VALUES ('jpotter','9b38e2b1e8b12f426b0d208a7ab6cb98');
COMMIT;
