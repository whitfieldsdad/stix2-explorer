<!-- omit in toc -->
# stix2-to-networkx

A Python library for converting STIX 2 bundles into directed acyclic graphs (DAGs) using NetworkX.

- [Features](#features)
- [Command line interface](#command-line-interface)
  - [List object aliases](#list-object-aliases)
  - [List triples](#list-triples)
  - [List quads](#list-quads)

## Features

- Import STIX 2 bundles from files or URLs into NetworkX as directed acyclic graphs (DAGs).
- List edges between objects as triples or quads.

## Command line interface

```shell
poetry run stix2-to-digraph --help
Usage: stix2-to-digraph [OPTIONS] COMMAND [ARGS]...

Options:
  --indent INTEGER
  --help            Show this message and exit.

Commands:
  aliases  Get map of names/aliases/external IDs to object UUIDs.
  quads    Get quads.
  triples  Get triples.
```

The following commands are all equivalent:

```shell
poetry run stix2-to-digraph
poetry run converter
poetry run tool
poetry run script
```

### List object aliases

```shell
poetry run stix2-to-digraph aliases --help
Usage: stix2-to-digraph aliases [OPTIONS] [PATHS]...

  Get map of names/aliases/external IDs to object UUIDs.

Options:
  --allow-deprecated / --no-deprecated
                                  [default: no-deprecated]
  --allow-revoked / --no-revoked  [default: no-revoked]
  --include-names / --no-names    [default: include-names]
  --lowercase / --no-lowercase    [default: lowercase]
  --help                          Show this message and exit.
```

To list names, aliases, and external IDs to object UUIDs with CSV output:

```shell
poetry run stix2-to-digraph aliases https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --output-format=csv
```

```csv
/etc/passwd and /etc/shadow,attack-pattern--d0b4fcdb-d67d-4ed2-99ce-788b12f8c0f4
2015 ukraine electric power attack,campaign--46421788-b6e1-4256-b351-f8beffd1afba
2016 ukraine electric power attack,campaign--aa73efef-1418-4dbe-b43c-87a498e97234
...
```

To list names, aliases, and external IDs to object UUIDs with JSON output:

```shell
{
    "/etc/passwd and /etc/shadow": "attack-pattern--d0b4fcdb-d67d-4ed2-99ce-788b12f8c0f4",
    "2015 ukraine electric power attack": "campaign--46421788-b6e1-4256-b351-f8beffd1afba",
    "2016 ukraine electric power attack": "campaign--aa73efef-1418-4dbe-b43c-87a498e97234",
...
```

To list external IDs to object UUIDs with CSV output:

```shell
poetry run stix2-to-digraph aliases https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --output-format=csv --no-names
```

```csv
c0001,campaign--26d9ebae-de59-427f-ae9a-349456bae4b1
c0002,campaign--ae407e32-87e0-4d92-8705-3ae25d504d8a
c0004,campaign--f9cc545e-b0ef-4b92-8884-a3a4427609f6
```

To list external IDs to object UUIDs with TSV output:

```shell
poetry run stix2-to-digraph aliases https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --output-format=tsv --no-names
```

```csv
c0001   campaign--26d9ebae-de59-427f-ae9a-349456bae4b1
c0002   campaign--ae407e32-87e0-4d92-8705-3ae25d504d8a
c0004   campaign--f9cc545e-b0ef-4b92-8884-a3a4427609f6
...
```

To list external IDs to object UUIDs with JSON output:

```shell
poetry run stix2-to-digraph aliases https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --output-format=json --no-names
```

```json
{
    "c0001": "campaign--26d9ebae-de59-427f-ae9a-349456bae4b1",
    "c0002": "campaign--ae407e32-87e0-4d92-8705-3ae25d504d8a",
    "c0004": "campaign--f9cc545e-b0ef-4b92-8884-a3a4427609f6",
...
```

### List triples

Triples are a way of representing a directed graph as a list of subject-predicate-object triples.

The following options are available when listing triples:

```shell
poetry run stix2-to-digraph triples --help
```

```text
Usage: stix2-to-digraph triples [OPTIONS] [PATHS]...

  Get triples.

Options:
  --allow-deprecated / --no-deprecated
                                  [default: no-deprecated]
  --allow-revoked / --no-revoked  [default: no-revoked]
  --separator TEXT                [default:       ]
  --tabs
  --help                          Show this message and exit.
```

To list all triples:

```shell
poetry run stix2-to-digraph triples https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | head
```

```csv
attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298    subtechnique-of attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d
attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9    subtechnique-of attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9
attack-pattern--005cc321-08ce-4d17-b1ea-cb5275926520    subtechnique-of attack-pattern--451a9977-d255-43c9-b431-66de80130c8c
```

To list all malware used by FIN7 with a comma separating triples:

```shell
poetry run stix2-to-digraph triples https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --separator=, | grep 
```

```csv
intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--bd7a9e13-69fa-4243-a5e5-04326a63f9f2
intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--f559f945-eb8b-48b1-904c-68568deebed3
intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--f74a5069-015d-4404-83ad-5ca01056c0dc
...
```

### List quads

Quads are a way of representing a directed graph as a list of context-subject-predicate-object quads.

The following options are available when listing quads:

```shell
poetry run stix2-to-digraph quads --help
```

```shell
Usage: stix2-to-digraph quads [OPTIONS] [PATHS]...

  Get quads.

Options:
  --namespace TEXT                [required]
  --allow-deprecated / --no-deprecated
                                  [default: no-deprecated]
  --allow-revoked / --no-revoked  [default: no-revoked]
  --separator TEXT                [default:       ]
  --tabs
  --help                          Show this message and exit.
```

To list all quads:

```shell
poetry run stix2-to-digraph quads https://raw.githubusercontent.com/mitre-attack/attack-
stix-data/master/enterprise-attack/enterprise-attack.json --namespace=29b3f2c2-55c0-479b-863f-7b49a4277cb3 | head
```

```csv
29b3f2c2-55c0-479b-863f-7b49a4277cb3    attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298    subtechnique-of attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d
29b3f2c2-55c0-479b-863f-7b49a4277cb3    attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9    subtechnique-of attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9
29b3f2c2-55c0-479b-863f-7b49a4277cb3    attack-pattern--005cc321-08ce-4d17-b1ea-cb5275926520    subtechnique-of attack-pattern--451a9977-d255-43c9-b431-66de80130c8c
```

To list all malware used by FIN7 with a namespace of `29b3f2c2-55c0-479b-863f-7b49a4277cb3` and a comma separating quads:

```shell
poetry run stix2-to-digraph quads https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json --separator=, --namespace=29b3f2c2-55c0-479b-863f-7b49a4277cb3 | grep intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc | grep malware
```

```csv
29b3f2c2-55c0-479b-863f-7b49a4277cb3,intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--04fc1842-f9e4-47cf-8cb8-5c61becad142
29b3f2c2-55c0-479b-863f-7b49a4277cb3,intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--065196de-d7e8-4888-acfb-b2134022ba1b
29b3f2c2-55c0-479b-863f-7b49a4277cb3,intrusion-set--3753cc21-2dae-4dfb-8481-d004e74502cc,uses,malware--0ced8926-914e-4c78-bc93-356fb90dbd1f
...
```
