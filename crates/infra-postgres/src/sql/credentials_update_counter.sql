UPDATE credentials
SET passkey = jsonb_set(passkey, '{counter}', $1::text::jsonb)
WHERE id = $2;
