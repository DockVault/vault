-- Add ECC team key management columns to vaults table
-- Run this migration to support hierarchical key wrapping

ALTER TABLE vaults 
ADD COLUMN IF NOT EXISTS key_wrapping_mode VARCHAR(20) DEFAULT 'direct';

ALTER TABLE vaults 
ADD COLUMN IF NOT EXISTS member_keys JSON;

ALTER TABLE vaults 
ADD COLUMN IF NOT EXISTS team_key TEXT;

-- Add comment for documentation
COMMENT ON COLUMN vaults.key_wrapping_mode IS 'Key wrapping mode: direct or hierarchical';
COMMENT ON COLUMN vaults.member_keys IS 'Per-member encrypted vault keys (ECC)';
COMMENT ON COLUMN vaults.team_key IS 'Encrypted team key (hierarchical mode)';
