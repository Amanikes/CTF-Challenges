'use strict';

/**
 * Synthetic Meridian Technologies workspace data.
 *
 * This module holds only data that is safe to publish through the public
 * project API. The internal project record lives in server.js next to the
 * intentionally exposed endpoint.
 */

const workspace = {
  organization: 'Meridian Technologies',
  workspace: 'Product & Platform',
  user: {
    name: 'Priya Raman',
    role: 'Programme Director',
    initials: 'PR',
    email: 'priya.raman@meridian.example',
    timezone: 'Europe/Amsterdam'
  },
  metrics: [
    { id: 'active-projects', label: 'Active projects', value: '7', delta: '+2 this quarter', trend: 'up' },
    { id: 'open-tasks', label: 'Open tasks', value: '148', delta: '32 due this week', trend: 'flat' },
    { id: 'on-track', label: 'On track', value: '86%', delta: '+4% vs last month', trend: 'up' },
    { id: 'budget', label: 'Budget used', value: '62%', delta: 'of FY26 allocation', trend: 'flat' }
  ],
  projects: [
    {
      id: 'PRJ-1042',
      name: 'Helios Data Platform',
      code: 'HEL',
      status: 'Active',
      health: 'on-track',
      owner: 'Data Engineering',
      lead: 'Marta Kowalski',
      progress: 68,
      due: '2026-12-19',
      members: 14,
      priority: 'High',
      description: 'Consolidated warehouse and streaming pipeline for product analytics.'
    },
    {
      id: 'PRJ-1038',
      name: 'Atlas Billing Migration',
      code: 'ATL',
      status: 'Active',
      health: 'at-risk',
      owner: 'Revenue Systems',
      lead: 'Daniel Osei',
      progress: 41,
      due: '2026-11-28',
      members: 9,
      priority: 'High',
      description: 'Move legacy invoicing to the usage-based billing service.'
    },
    {
      id: 'PRJ-1031',
      name: 'Meridian Mobile 3.0',
      code: 'M3',
      status: 'Active',
      health: 'on-track',
      owner: 'Mobile Experience',
      lead: 'Sofia Almeida',
      progress: 77,
      due: '2027-01-16',
      members: 18,
      priority: 'Medium',
      description: 'Design-system refresh and offline-first sync for the mobile client.'
    },
    {
      id: 'PRJ-1024',
      name: 'Sentinel Access Review',
      code: 'SEN',
      status: 'Active',
      health: 'on-track',
      owner: 'Security Engineering',
      lead: 'Tomas Berg',
      progress: 55,
      due: '2026-12-05',
      members: 6,
      priority: 'High',
      description: 'Quarterly entitlement review and least-privilege clean-up.'
    },
    {
      id: 'PRJ-1019',
      name: 'Kepler Reporting Suite',
      code: 'KEP',
      status: 'Planned',
      health: 'on-track',
      owner: 'Product Analytics',
      lead: 'Ana Duarte',
      progress: 12,
      due: '2027-03-08',
      members: 7,
      priority: 'Medium',
      description: 'Self-service reporting surface for customer success teams.'
    },
    {
      id: 'PRJ-1008',
      name: 'Vega Design Tokens',
      code: 'VEG',
      status: 'Completed',
      health: 'on-track',
      owner: 'Design Systems',
      lead: 'Liam Fraser',
      progress: 100,
      due: '2026-09-30',
      members: 5,
      priority: 'Low',
      description: 'Shared token pipeline consumed by web and mobile surfaces.'
    }
  ],
  tasks: [
    {
      id: 'TSK-8841',
      title: 'Finalise streaming schema for event ingestion',
      project: 'Helios Data Platform',
      projectCode: 'HEL',
      assignee: 'Marta Kowalski',
      status: 'In progress',
      priority: 'High',
      due: '2026-11-14'
    },
    {
      id: 'TSK-8836',
      title: 'Reconcile invoice totals for legacy accounts',
      project: 'Atlas Billing Migration',
      projectCode: 'ATL',
      assignee: 'Daniel Osei',
      status: 'Blocked',
      priority: 'High',
      due: '2026-11-12'
    },
    {
      id: 'TSK-8829',
      title: 'Publish offline sync conflict rules',
      project: 'Meridian Mobile 3.0',
      projectCode: 'M3',
      assignee: 'Sofia Almeida',
      status: 'In review',
      priority: 'Medium',
      due: '2026-11-18'
    },
    {
      id: 'TSK-8821',
      title: 'Export privileged role matrix for review',
      project: 'Sentinel Access Review',
      projectCode: 'SEN',
      assignee: 'Tomas Berg',
      status: 'In progress',
      priority: 'High',
      due: '2026-11-20'
    },
    {
      id: 'TSK-8814',
      title: 'Draft reporting API contract',
      project: 'Kepler Reporting Suite',
      projectCode: 'KEP',
      assignee: 'Ana Duarte',
      status: 'Not started',
      priority: 'Medium',
      due: '2026-12-02'
    }
  ],
  activity: [
    { id: 'ACT-3', at: '2026-11-10T08:42:00Z', actor: 'Marta Kowalski', text: 'moved TSK-8841 to In progress', project: 'HEL' },
    { id: 'ACT-2', at: '2026-11-09T16:10:00Z', actor: 'Daniel Osei', text: 'flagged a dependency on Atlas billing', project: 'ATL' },
    { id: 'ACT-1', at: '2026-11-08T11:05:00Z', actor: 'Priya Raman', text: 'published the Q4 portfolio review', project: 'Portfolio' }
  ]
};

module.exports = { workspace };
