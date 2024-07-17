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

CREATE OR REPLACE TABLE matrices AS (
    SELECT * FROM objects WHERE type = 'x-mitre-matrix'
);

CREATE OR REPLACE TABLE tactics AS (
    SELECT * FROM objects WHERE type = 'x-mitre-tactic'
);

CREATE OR REPLACE TABLE techniques AS (
    SELECT * FROM objects WHERE type = 'attack-pattern'
);

CREATE OR REPLACE TABLE mitigations AS (
    SELECT * FROM objects WHERE type = 'course-of-action'
);

CREATE OR REPLACE TABLE malware AS (
    SELECT * FROM objects WHERE type = 'malware'
);

CREATE OR REPLACE TABLE tools AS (
    SELECT * FROM objects WHERE type = 'tool'
);

CREATE OR REPLACE TABLE data_sources AS (
    SELECT * FROM objects WHERE type = 'x-mitre-data-source'
);

CREATE OR REPLACE TABLE data_components AS (
    SELECT * FROM objects WHERE type = 'x-mitre-data-component'
);

CREATE OR REPLACE TABLE campaigns AS (
    SELECT * FROM objects WHERE type = 'campaign'
);

COPY objects TO 'data/mitre-attack-enterprise/objects.csv' WITH HEADER;
COPY matrices TO 'data/mitre-attack-enterprise/matrices.csv' WITH HEADER;
COPY tactics TO 'data/mitre-attack-enterprise/tactics.csv' WITH HEADER;
COPY techniques TO 'data/mitre-attack-enterprise/techniques.csv' WITH HEADER;
COPY mitigations TO 'data/mitre-attack-enterprise/mitigations.csv' WITH HEADER;
COPY malware TO 'data/mitre-attack-enterprise/malware.csv' WITH HEADER;
COPY tools TO 'data/mitre-attack-enterprise/tools.csv' WITH HEADER;
COPY data_sources TO 'data/mitre-attack-enterprise/data_sources.csv' WITH HEADER;
COPY data_components TO 'data/mitre-attack-enterprise/data_components.csv' WITH HEADER;
COPY campaigns TO 'data/mitre-attack-enterprise/campaigns.csv' WITH HEADER;
