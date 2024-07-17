CREATE OR REPLACE TABLE objects AS (
    SELECT 
        id,
        type,
        name
    FROM (
        SELECT 
            id,
            type,
            name,
        FROM (
            SELECT
                UNNEST(objects, recursive := true) AS object
            FROM read_json_auto('data/mitre-attack-enterprise/enterprise-attack.json', maximum_object_size=1073741824)
        )
    ) 
    WHERE type NOT IN ('relationship')
);

CREATE OR REPLACE TABLE object_external_ids AS (
    SELECT 
        id,
        external_reference.external_id AS external_id,
    FROM (
        SELECT 
            id,
            UNNEST(external_references) AS external_reference
        FROM (
            SELECT
                UNNEST(objects, recursive := true) AS object
            FROM read_json_auto('data/mitre-attack-enterprise/enterprise-attack.json', maximum_object_size=1073741824)
        )
    )
    WHERE external_reference.source_name = 'mitre-attack'
);

ALTER TABLE objects ADD COLUMN external_id STRING;

UPDATE objects 
SET external_id = object_external_ids.external_id 
FROM object_external_ids 
WHERE objects.id = object_external_ids.id;

COPY objects TO 'data/mitre-attack-enterprise/objects.csv' WITH HEADER;
