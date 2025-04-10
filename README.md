# gMSAbuse
PS script designed to enumerate gMSA(s) in an AD environment and identify overly permissive accounts that the current user can abuse.<br>
Script follows this articles methodology: [Abusing and Securing Group Managed Service Accounts](https://blog.netwrix.com/2022/10/13/group-managed-service-accounts-gmsa/).

## Methodology
- Identify current user & their membership(s)
- Enumerate gMSA(s) in the domain that have group memberships
- Check if current user has permission to modify gMSA attributes
  - GenericAll, WriteProperty, WriteProperty on mdDS-GroupMSAMembership attribute
- Report vulnerable gMSA(s) with potential to abuse

## Credit
[Kevin Joyce](https://github.com/kdejoyce) for [gMSA_Permissions_Collection.ps1](https://gist.github.com/kdejoyce/f0b8f521c426d04740148d72f5ea3f6f#file-gmsa_permissions_collection-ps1) script base
