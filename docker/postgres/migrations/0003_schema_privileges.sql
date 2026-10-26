-- Nobody but the owner creates objects in public; the API only uses them.
-- (Databases made by the old init script already had this.)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO api;
