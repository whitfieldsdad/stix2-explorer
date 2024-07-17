default: docs data

up:
	docker-compose up

down:
	docker-compose down

docs:
	./scripts/render-all-dot-files.sh

data:
	cp ~/src/attack-stix-data/enterprise-attack/enterprise-attack.json data/mitre-attack-enterprise/enterprise-attack.json
	python3 examples/get_mitre_attack_enterprise_matrix.py -o data/mitre-attack-enterprise/mappings.csv
	python3 examples/get_mitre_capec_matrix.py -o data/mitre-capec/mappings.csv
	python3 examples/get_mitre_mbc_matrix.py -o data/mitre-mbc/mappings.csv
	python3 examples/get_mitre_attack_enterprise_to_nist_sp_800_53_matrix.py -o data/mitre-attack-enterprise-to-nist-sp-800-53-r5/mappings.csv
	python3 examples/get_nist_sp_800_53_matrix.py -o data/nist-sp-800-53-r5/mappings.csv
	duckdb < scripts/process-mitre-attack-enterprise.sql
	duckdb < scripts/process-mitre-attack-enterprise-to-nist-sp-800-53-r5-mappings.sql
	duckdb < scripts/process-mitre-attack-enterprise-mappings.sql
	duckdb < scripts/process-mitre-capec-mappings.sql
	duckdb < scripts/process-mitre-mbc-mappings.sql
	duckdb < scripts/process-nist-sp-800-53-r5-mappings.sql

.PHONY: data docs
