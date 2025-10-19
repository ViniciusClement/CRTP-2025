## Basic Content AD

**AD**
- Active Directory is a service to manage Windows domain networks. It permits the authentication of computers in the network using relative credentials via Kerberos tickets methodology.

**SCHEMA**
- Schema defines the structure of the directory by specifying the types of objects (e.g., users, computers, groups) and their attributes (e.g., username, email, security ID).

**QUERY AND INDEX MECHANISM**
- This mechanism allows efficient searching and organization of data in the directory. Queries are typically made using LDAP (Lightweight Directory Access Protocol)

**REPLICATION SERVICE** 
- The replication service synchronizes changes between domain controllers within a domain and across the forest. It ensures high availability and consistency of data

**FORESTS**
- A forest consists of one or more domains that share a common schema, configuration, and Global Catalog.

**DOMAINS**
- Subsets within a forest that serve as administrative boundaries. Each domain has its own unique policies and authentication services but shares the forest's schema and configuration.

** ORGANIZATIONAL UNITS (OUs)** 
- Containers within a domain used to organize and manage objects.

**DOMAIN CONTROLLER (DC)**
- When a server is promoted to a domain controller, it assumes several key functions entrusted with the Active Directory Domain Services (AD DS) server role.

**TREES** 
- A Tree is a collection of domains that share a contiguous namespace and a common schema. For example:

* example.com
* sales.example.com
* hr.example.com

**DOMAIN TRUSTS** 
- Trusts allow users in one domain or forest to access resources in another securely.

* Parent-Child Trust – Automatically created between a parent and child domain.
* Tree-Root Trust – Automatically created when a new domain tree is added.
* External Trust – Manually created to connect two separate domains.
* Forest Trust – Manually created between forests for cross-domain authentication.