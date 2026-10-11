# Opt-in Delegation coordination above hosting CRUD

Consumers previously owned all Delegation coordination. An explicit `delegation`
workflow now centralizes planning, ordering, verification and progress above
caller-selected hosting and registrar Accounts, while ordinary Zone CRUD keeps
its hosting-only scope. This expands the module's public boundary to reduce
repeated safety logic without hiding cross-Account writes in hosting operations;
consumers still own confirmation and supply bounded DNS observations and any
Nameserver-writing adapter.

The Nameserver adapter is provisional: no production vendor adapter is delivered.
Plans and progress retain process-local evidence rather than durable jobs, and
independent writes remain nontransactional. DNSSEC transitions are deliberately
conservative: verified trust paths are required and changes to an existing held DS
set are blocked because DSRegistrar supplies no intermediate-write guarantee.
Initial publication checks every independently publishable form; partial writes
remain observed progress rather than authorizing an unsupported repair. Arbitrary
key rollover is excluded and unsupported work remains explicit.
