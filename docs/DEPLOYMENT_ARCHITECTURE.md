\# AegisGuard Deployment Architecture



\## Overview



AegisGuard supports multiple deployment models based on organization size, log volume, and operational requirements.



\---



\# Deployment Models



\## 1. Single Server Deployment



Suitable for:



\- Small organizations

\- Testing environments

\- Limited log sources





Architecture:





Users

|

v

AegisGuard UI

|

v

Backend Services

|

+-------------+

| |

Detection Storage

Engine

|

Collectors





\---



\## 2. Enterprise Server Deployment



Suitable for:



\- SOC environments

\- Multiple security devices

\- Continuous monitoring





Architecture:





Security Devices

|

v

Collectors

|

v

Processing Layer

|

+----------------+

| |

Detection Engine Storage

|

v

SOC Dashboard





\---



\## 3. Distributed Deployment



Suitable for:



\- Large environments

\- Multiple collection points





Architecture:





Collector Node 1 ----

Collector Node 2 -----

Collector Node 3 ------> Processing Cluster

Collector Node N -----/



&#x20;        |

&#x20;        v



&#x20;  Central Storage



&#x20;        |

&#x20;        v



&#x20;  SOC Dashboard



\---



\# Air-Gapped Deployment



AegisGuard supports controlled offline environments.



Characteristics:



\- No external cloud dependency

\- Internal network operation

\- Local data processing

\- Local evidence storage



\---



\# Data Flow





Input Logs



&#x20;|



Collectors



&#x20;|



Processing Pipeline



&#x20;|



Detection Engine



&#x20;|



Incident Management



&#x20;|



SOC Analyst

