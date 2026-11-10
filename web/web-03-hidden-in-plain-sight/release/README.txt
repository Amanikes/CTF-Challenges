MERIDIAN TECHNOLOGIES — WEB-03 "HIDDEN IN PLAIN SIGHT"
=====================================================

Category: Web Exploitation
Difficulty: Easy
Points: 50
Flag format: AXUM{...}

------------------------------------------------------------
PARTICIPANT INFORMATION
------------------------------------------------------------

Meridian Technologies recently deployed a new project-management portal.

The development team has been working on several features that are not yet
available to regular users. Following the latest deployment, some application
resources may have been exposed unintentionally.

Your task is to investigate the portal and uncover information that was never
intended to be publicly accessible.

Objective: Find the exposed internal project information and retrieve the flag.

Hint
  Sometimes the browser receives more information than the interface actually
  displays.

  Take a closer look at the resources loaded by the application.

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
  - tests/        local Docker suite, bundle check and GZ::CTF validation

Deployment summary
  - Build source/ and push the image to a registry reachable by GZ::CTF.
  - Create a DynamicContainer challenge with:
      Flag template  AXUM{hidden_in_plain_sight_[TEAM_HASH]}
      Service port   3000
      Memory         128 MB
      CPU            1 (0.1 CPUs)
      Storage        64 MB
      Network        Open
  - Set ContainerProvider.PublicEntry to the player-facing host.
  - See organizer/DEPLOYMENT.md for exact fields and API calls.

Version
  - Verified against GZ::CTF 1.9.1.
  - Application image: node:22-alpine, runs as uid 1000, no EXPOSE.

Do not publish organizer/ before the competition ends.
