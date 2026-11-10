NORTHSTAR BANK — WEB-02 "NOT YOUR ACCOUNT"
==========================================

Category: Web Exploitation
Difficulty: Easy
Points: 50
Flag format: AXUM{...}

------------------------------------------------------------
PARTICIPANT INFORMATION
------------------------------------------------------------

Northstar Bank recently launched a new online banking portal for its
customers.

The portal allows customers to log in, review their account information, and
inspect recent transactions. The development team believes the application is
ready for production.

However, a security review has raised concerns about how the application
retrieves customer account records.

You've been provided with a test account to investigate the portal.

Your objective: Explore the application, identify the access-control weakness,
and retrieve the information belonging to another customer.

Test credentials
  Username: alex
  Password: Northstar@2026

Hints
  1. Being authenticated does not necessarily mean you're authorized to access
     every resource.
  2. Inspect the requests your browser makes when loading account information.
  3. Pay attention to how the application identifies which account to retrieve.

Submit the flag you discover.

------------------------------------------------------------
ORGANIZER RELEASE NOTES
------------------------------------------------------------

Package contents (participant distribution)
  - This README.
  - The challenge instance URL provided by the platform.

Package contents (organizer archive)
  - source/       application and Dockerfile
  - challenge.yml deployment values (not an importable GZ::CTF format)
  - organizer/    writeup, testing report and deployment guide (SPOILERS)
  - tests/        local Docker suite and GZ::CTF two-team validation script

Deployment summary
  - Build source/ and push the image to a registry reachable by GZ::CTF.
  - Create a DynamicContainer challenge with:
      Flag template  AXUM{not_your_account_[TEAM_HASH]}
      Service port   3000
      Memory         128 MB
      CPU            1 (0.1 CPUs)
      Storage        64 MB
      Network        Open
  - Set ContainerProvider.PublicEntry to the player-facing host.
  - See organizer/DEPLOYMENT.md for the exact fields and API calls.

Version
  - Verified against GZ::CTF 1.9.1.
  - Application image: node:22-alpine, runs as uid 1000, no EXPOSE.

Do not publish organizer/ before the competition ends.
