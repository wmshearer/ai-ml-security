# The framework these playbooks map to

Every playbook here maps to NIST SP 800-61 Revision 3. That choice needs
explaining, because most incident response material you will find online maps to
something that has been superseded.

## The four phases are Revision 2, and Revision 2 is withdrawn

The lifecycle almost everyone quotes goes Preparation, Detection and Analysis,
Containment Eradication and Recovery, then Post-Incident Activity. Four phases,
often drawn as a loop.

That is NIST SP 800-61 Revision 2, published August 2012. Revision 3 supersedes
it. From the front matter of Revision 3 itself:

> Supersedes NIST SP 800-61r2 (August 2012)

Revision 3 is titled "Incident Response Recommendations and Considerations for
Cybersecurity Risk Management: A CSF 2.0 Community Profile" and was published in
April 2025.

## What replaced it

Revision 3 organises incident response around the six CSF 2.0 Functions rather
than a phase sequence. Quoting the document's own definitions:

- **Govern (GV)**: the organization's cybersecurity risk management strategy, expectations, and policy
- **Identify (ID)**: the organization's current cybersecurity risks are understood
- **Protect (PR)**: safeguards to manage the organization's cybersecurity risks are used
- **Detect (DE)**: possible cybersecurity attacks and compromises are found and analyzed
- **Respond (RS)**: actions regarding a detected cybersecurity incident are taken
- **Recover (RC)**: assets and operations affected by a cybersecurity incident are restored

The executive summary splits them by role:

> Govern, Identify, and Protect help organizations prevent some incidents, prepare
> to handle incidents that do occur, reduce the impact of those incidents, and
> improve incident response and cybersecurity risk management practices based on
> lessons learned from those incidents.

> Detect, Respond, and Recover help organizations discover, manage, prioritize,
> contain, eradicate, and recover from cybersecurity incidents

## The old phases still map cleanly

Revision 3 provides the crosswalk itself, in Table 1:

| Revision 2 phase | CSF 2.0 Functions |
|---|---|
| Preparation | Govern, Identify (all Categories), Protect |
| Detection and Analysis | Detect, Identify (Improvement Category) |
| Containment, Eradication and Recovery | Respond, Recover, Identify (Improvement Category) |
| Post-Incident Activity | Identify (Improvement Category) |

## NIST does not say you must switch

This is the part usually lost when people cite the change:

> Organizations should use the incident response life cycle framework or model
> that suits them best. The model in this document is based on CSF 2.0 to take
> advantage of the wealth of resources available for CSF 2.0 and aid organizations
> that are already using the CSF.

So the correct statement is not "the four phases are wrong." It is that Revision 2
is withdrawn, Revision 3 uses the CSF Functions, and an organisation may still use
whichever model fits, as long as it knows which document it is citing.

These playbooks use the Functions, and each step names the Function it belongs to.

## Source

NIST SP 800-61r3, April 2025. Nelson, Rekhi, Souppaya, Scarfone.
https://doi.org/10.6028/NIST.SP.800-61r3

Every quotation above was taken from the published PDF, not from secondary
summaries of it.
