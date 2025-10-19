### Domain Enumeration - Trusts

In an AD environment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

### One-way trust

One-way trust - Unidirectional. Users in the trusted domain can access resources in the trusting domain but the reverse is not true

<img width="1064" height="419" alt="image" src="https://github.com/user-attachments/assets/3af9659b-0072-42b1-9407-bc80ec462bc3" />


### Two-way trust

Two-way trust - Bi-directional. Users of both domains can access resources in the other domain.

<img width="1167" height="444" alt="image" src="https://github.com/user-attachments/assets/68a37835-1a13-4840-9b4e-5d2cf01464b5" />


### Transitivity

**Transitive** - Can be extended to establish trust relationships with other domains.
- All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains within a same forest are transitive two-way trusts

**Nontransitive** - Cannot be extended to other domains in the forest. Can be two-way or one-way.
- This is the default trust (called external trust) between two domains in different forests when forests do not have a trust relationship.

<img width="651" height="572" alt="image" src="https://github.com/user-attachments/assets/30d3c431-8382-46a1-ba63-559af0094ca1" />


**Parent-child trust**

It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy, whenever a new domain is added in a tree. 

* Ex: dollarcorp.moneycorp.local is a child of moneycorp.local

This trust is always two-way transitive.

**Tree-root trust**

It is created automatically between whenever a new domain tree is added to a forest root.

This trust is always two-way transitive

<img width="1228" height="647" alt="image" src="https://github.com/user-attachments/assets/131b3361-e7d2-4a5b-abcf-21bc175fd308" />


**External Trust**

Between two domains in different forests when forests do not have a trust relationship.
- Can be one-way or two-way and is nontransitive.

<img width="987" height="558" alt="image" src="https://github.com/user-attachments/assets/7dc6b88b-a3f2-4e58-b96d-f064cb0b6da3" />


**Forest Trust**

* Between forest root domain.

* Cannot be extended to a third forest (no implicit trust).

* Can be one-way or two-way transitive.

<img width="1094" height="363" alt="image" src="https://github.com/user-attachments/assets/bb3f5c5f-0deb-4c49-a455-2643aa5eefff" />

Get a list of all domain trusts for the current domain
* Get-DomainTrust
* Get-DomainTrust -Domain us.dollarcorp.moneycorp.local

Get details about the current forest
* Get-Forest
* Get-Forest -Forest eurocorp.local

Get all domains in the current forest
* Get-ForestDomain
* Get-ForestDomain -Forest eurocorp.local (Get-ADForest).Domains

Get all global catalogs for the current forest
* Get-ForestGlobalCatalog
* Get-ForestGlobalCatalog -Forest eurocorp.local

Map trusts of a forest (no Forest trusts in the lab)
* Get-ForestTrust
* Get-ForestTrust -Forest eurocorp.local