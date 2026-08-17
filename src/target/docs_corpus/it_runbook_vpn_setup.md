# IT Runbook: VPN Setup — Synthetic Test Fixture

**Document ID:** IT-RB-007
**Effective:** synthetic / not a real company

New employees at Acme Testing Corp (fictional) receive VPN client credentials
during onboarding week 1. The VPN client (fictional internal tool, "AcmeConnect")
should be configured to auto-connect on login for company-issued laptops.

If AcmeConnect fails to connect, restart the client, confirm the laptop's clock
is synced (certificate validation fails on clock skew > 5 minutes), and if the
issue persists, open a ticket with the helpdesk assistant including the error
code shown in the client's log panel.
