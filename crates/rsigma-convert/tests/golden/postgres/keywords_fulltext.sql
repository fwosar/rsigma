SELECT * FROM security_events WHERE to_tsvector('simple', ROW(*)::text) @@ plainto_tsquery('simple', 'whoami') OR to_tsvector('simple', ROW(*)::text) @@ plainto_tsquery('simple', 'ipconfig')
