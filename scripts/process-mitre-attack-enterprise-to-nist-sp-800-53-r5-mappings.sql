CREATE OR REPLACE TABLE controls AS (
    SELECT 
        target_object_external_id AS control_id,
        target_object_name AS control_name,
    FROM 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mappings.csv' 
    WHERE source_dataset = 'nist-sp-800-53-r5' AND target_dataset = 'nist-sp-800-53-r5' AND relationship = 'subcontrol-of'
    GROUP BY *
);

CREATE OR REPLACE TABLE subcontrols AS (
    SELECT 
        target_object_external_id AS control_id,
        target_object_name AS control_name,
        source_object_external_id AS subcontrol_id,
        string_split(source_object_name, ' | ')[-1] AS subcontrol_name,
    FROM 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mappings.csv' 
    WHERE source_dataset = 'nist-sp-800-53-r5' AND target_dataset = 'nist-sp-800-53-r5' AND relationship = 'subcontrol-of'
);

CREATE OR REPLACE TABLE controls_to_techniques AS (
    SELECT 
        source_object_external_id AS control_id,
        source_object_name AS control_name,
        relationship,
        target_object_external_id AS technique_id,
        target_object_name AS technique_name,
    FROM 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mappings.csv' 
    WHERE source_dataset != target_dataset
);

CREATE OR REPLACE TABLE subcontrols_to_techniques AS (
    SELECT s.control_id, s.control_name, s.subcontrol_id, s.subcontrol_name, c.technique_id, c.technique_name 
    FROM subcontrols s 
    JOIN controls_to_techniques c ON s.control_id = c.control_id
);

CREATE OR REPLACE TABLE mapping_stats AS (
    SELECT 
        source_object_type, 
        relationship, 
        target_object_type, 
        COUNT(*) as total 
    FROM 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mappings.csv'  
    GROUP BY *
    ORDER BY total DESC
);

COPY mapping_stats TO 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mapping_stats.csv' WITH HEADER;
COPY controls TO 'data/nist-sp-800-53-r5/controls.csv' WITH HEADER;
COPY subcontrols TO 'data/nist-sp-800-53-r5/subcontrols.csv' WITH HEADER;
COPY controls_to_techniques TO 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/controls_to_techniques.csv' WITH HEADER;
COPY subcontrols_to_techniques TO 'data/mitre-attack-enterprise-to-nist-sp-800-53-r5/subcontrols_to_techniques.csv' WITH HEADER;