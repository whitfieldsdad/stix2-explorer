CREATE OR REPLACE TABLE mappings AS (
    SELECT 
        source_object_external_id, 
        source_object_name,
        source_object_type,
        relationship,
        target_object_external_id,
        target_object_name,
        target_object_type
    FROM 'data/nist-sp-800-53-r5/mappings.csv'
);

CREATE OR REPLACE TABLE mapping_stats AS (
    SELECT 
        source_object_type, 
        relationship, 
        target_object_type, 
        COUNT(*) as total 
    FROM mappings 
    GROUP BY *
    ORDER BY total DESC
);

COPY mapping_stats TO 'data/nist-sp-800-53-r5/mapping_stats.csv' WITH HEADER;