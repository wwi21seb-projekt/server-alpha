-- Database generated with pgModeler (PostgreSQL Database Modeler).
-- pgModeler version: 1.1.0-beta1
-- PostgreSQL version: 16.0
-- Project Site: pgmodeler.io
-- Model Author: ---
-- -- object: alpha | type: ROLE --
-- -- DROP ROLE IF EXISTS alpha;
-- CREATE ROLE alpha WITH 
-- 	CREATEDB
-- 	CREATEROLE
-- 	LOGIN;
-- -- ddl-end --
-- 

-- Database creation must be performed outside a multi lined SQL file. 
-- These commands were put in this file only as a convenience.
-- 
-- -- object: server_alpha_db | type: DATABASE --
-- -- DROP DATABASE IF EXISTS server_alpha_db;
-- CREATE DATABASE server_alpha_db
-- 	ENCODING = 'UTF8';
-- -- ddl-end --
-- 

-- object: alpha_schema | type: SCHEMA --
-- DROP SCHEMA IF EXISTS alpha_schema CASCADE;
CREATE SCHEMA alpha_schema;
-- ddl-end --
ALTER SCHEMA alpha_schema OWNER TO alpha;
-- ddl-end --

SET search_path TO pg_catalog,public,alpha_schema;
-- ddl-end --

-- object: alpha_schema.users | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.users CASCADE;
CREATE TABLE alpha_schema.users (
	user_id uuid NOT NULL,
	username varchar(25) NOT NULL,
	nickname varchar(20) NOT NULL,
	email varchar(128) NOT NULL,
	password char(60) NOT NULL,
	status varchar(256) NOT NULL,
	profile_picture_url varchar(256) NOT NULL,
	created_at timestamptz NOT NULL,
	activated_at timestamptz,
	expires_at timestamptz,
	CONSTRAINT user_id_pk PRIMARY KEY (user_id)
);
-- ddl-end --

-- object: alpha_schema.activation_tokens | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.activation_tokens CASCADE;
CREATE TABLE alpha_schema.activation_tokens (
	token_id uuid NOT NULL,
	token varchar(6) NOT NULL,
	expires_at timestamptz,
	user_id uuid NOT NULL,
	CONSTRAINT tokens_pk PRIMARY KEY (token_id)
);
-- ddl-end --

-- object: users_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.activation_tokens DROP CONSTRAINT IF EXISTS users_fk CASCADE;
ALTER TABLE alpha_schema.activation_tokens ADD CONSTRAINT users_fk FOREIGN KEY (user_id)
REFERENCES alpha_schema.users (user_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: alpha_schema.posts | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.posts CASCADE;
CREATE TABLE alpha_schema.posts (
	post_id uuid NOT NULL,
	content varchar(256),
	created_at timestamptz NOT NULL,
	author_id uuid NOT NULL,
	CONSTRAINT posts_pk PRIMARY KEY (post_id)
);
-- ddl-end --

-- object: alpha_schema.subscriptions | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.subscriptions CASCADE;
CREATE TABLE alpha_schema.subscriptions (
	subscription_id uuid NOT NULL,
	created_at timestamptz NOT NULL,
	subscriber_id uuid NOT NULL,
	subscribee_id uuid NOT NULL,
	CONSTRAINT subscriptions_pk PRIMARY KEY (subscription_id)
);
-- ddl-end --
COMMENT ON COLUMN alpha_schema.subscriptions.subscription_id IS E'TODO: Besprechen ob man das überhaupt braucht';
-- ddl-end --

-- object: users_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.posts DROP CONSTRAINT IF EXISTS users_fk CASCADE;
ALTER TABLE alpha_schema.posts ADD CONSTRAINT users_fk FOREIGN KEY (author_id)
REFERENCES alpha_schema.users (user_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: alpha_schema.hashtags | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.hashtags CASCADE;
CREATE TABLE alpha_schema.hashtags (
	hashtag_id uuid NOT NULL,
	content varchar(32) NOT NULL,
	CONSTRAINT hashtags_pk PRIMARY KEY (hashtag_id),
	CONSTRAINT hashtags_uq UNIQUE (content)
);
-- ddl-end --

-- object: alpha_schema.posts_and_hashtags | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.posts_and_hashtags CASCADE;
CREATE TABLE alpha_schema.posts_and_hashtags (
	post_id uuid NOT NULL,
	hashtag_id uuid NOT NULL,
	CONSTRAINT posts_and_hashtags_pk PRIMARY KEY (post_id,hashtag_id)
);
-- ddl-end --

-- object: posts_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.posts_and_hashtags DROP CONSTRAINT IF EXISTS posts_fk CASCADE;
ALTER TABLE alpha_schema.posts_and_hashtags ADD CONSTRAINT posts_fk FOREIGN KEY (post_id)
REFERENCES alpha_schema.posts (post_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: hashtags_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.posts_and_hashtags DROP CONSTRAINT IF EXISTS hashtags_fk CASCADE;
ALTER TABLE alpha_schema.posts_and_hashtags ADD CONSTRAINT hashtags_fk FOREIGN KEY (hashtag_id)
REFERENCES alpha_schema.hashtags (hashtag_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: alpha_schema.likes | type: TABLE --
-- DROP TABLE IF EXISTS alpha_schema.likes CASCADE;
CREATE TABLE alpha_schema.likes (
	user_id uuid NOT NULL,
	post_id uuid NOT NULL,
	liked_at timestamptz NOT NULL,
	CONSTRAINT likes_pk PRIMARY KEY (user_id,post_id)
);
-- ddl-end --

-- object: users_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.likes DROP CONSTRAINT IF EXISTS users_fk CASCADE;
ALTER TABLE alpha_schema.likes ADD CONSTRAINT users_fk FOREIGN KEY (user_id)
REFERENCES alpha_schema.users (user_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: posts_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.likes DROP CONSTRAINT IF EXISTS posts_fk CASCADE;
ALTER TABLE alpha_schema.likes ADD CONSTRAINT posts_fk FOREIGN KEY (post_id)
REFERENCES alpha_schema.posts (post_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: subscriber_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.subscriptions DROP CONSTRAINT IF EXISTS subscriber_fk CASCADE;
ALTER TABLE alpha_schema.subscriptions ADD CONSTRAINT subscriber_fk FOREIGN KEY (subscriber_id)
REFERENCES alpha_schema.users (user_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: subscribee_fk | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.subscriptions DROP CONSTRAINT IF EXISTS subscribee_fk CASCADE;
ALTER TABLE alpha_schema.subscriptions ADD CONSTRAINT subscribee_fk FOREIGN KEY (subscribee_id)
REFERENCES alpha_schema.users (user_id) MATCH FULL
ON DELETE CASCADE ON UPDATE CASCADE;
-- ddl-end --

-- object: subscriptions_uq | type: CONSTRAINT --
-- ALTER TABLE alpha_schema.subscriptions DROP CONSTRAINT IF EXISTS subscriptions_uq CASCADE;
ALTER TABLE alpha_schema.subscriptions ADD CONSTRAINT subscriptions_uq UNIQUE (subscriber_id,subscribee_id);
-- ddl-end --


