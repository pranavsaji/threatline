import type { CleanCase } from './cases.js';
import type { ExpectedThreat } from '../runner/metrics.js';

const e = (stride: ExpectedThreat['stride'], title: string, severity: ExpectedThreat['severity'], ...keywords: string[]): ExpectedThreat => ({ stride, title, severity, keywords });

/**
 * Fresh held-out set (2026-11-22): 10 clean cases written before the gap check and the stricter verifier were built or
 * run, and committed on their own so the history shows that. Nothing in the Engine was tuned on them. Same style as the
 * golden set: a few important threats per design, including the low-severity ones a reviewer would still ask for.
 */
export const FRESH_CASES: CleanCase[] = [
  {
    id: 'fresh-web-01', domain: 'web', summary: 'Magic-link sign-in for a customer portal',
    design: 'Customers sign in to the billing portal by entering their email address; we email them a sign-in link. The link opens the portal already signed in and stays valid for 7 days. The portal shows invoices and lets customers change the card on file. The sign-in page is public.',
    expected: [
      e('Spoofing', 'Intercepted or forwarded sign-in link gives account takeover', 'High', 'link', 'takeover', 'reuse', 'forward', 'valid for'),
      e('DenialOfService', 'Sign-in form abused to flood inboxes with emails', 'Low', 'flood', 'spam', 'rate', 'email bomb'),
      e('InformationDisclosure', 'Sign-in response reveals which emails are customers', 'Low', 'enumerat', 'exists'),
    ],
  },
  {
    id: 'fresh-web-02', domain: 'web', summary: 'Support ticket attachments viewed by agents',
    design: 'Customers open support tickets on our website and can attach any file. Support agents open the attachments in the agent console, which runs in their browser with access to every customer record. Attachments are stored in a public-read storage bucket so the console can link to them directly.',
    expected: [
      e('InformationDisclosure', 'Public-read bucket exposes every customer attachment', 'High', 'public', 'bucket', 'read'),
      e('ElevationOfPrivilege', 'Malicious attachment runs script in the agent console', 'High', 'script', 'html', 'svg', 'xss', 'agent console', 'malware'),
      e('Repudiation', 'No record of which agent viewed which customer files', 'Low', 'audit', 'log', 'record'),
    ],
  },
  {
    id: 'fresh-api-01', domain: 'api', summary: 'Partner API for creating shipments',
    design: 'Logistics partners call POST /shipments with an API key to create shipments for our merchants. The request names the merchantId to bill and the declared value. Each partner works for several merchants. Shipments are billed to the merchant automatically.',
    expected: [
      e('ElevationOfPrivilege', 'Partner bills shipments to a merchant it does not serve', 'High', 'merchantid', 'merchant', 'another merchant', 'idor', 'bill'),
      e('Tampering', 'Declared value manipulated to change charges or insurance', 'Medium', 'declared value', 'value'),
      e('Repudiation', 'Partner denies creating shipments billed to a merchant', 'Low', 'audit', 'repudiat', 'record', 'deny'),
    ],
  },
  {
    id: 'fresh-api-02', domain: 'api', summary: 'Public search API with free-text filters',
    design: 'The catalogue search API is public. Clients pass a filter string such as "price < 20 AND brand = acme"; the service turns the filter into a database query with string templates. Results are paged 500 at a time with no limit on how many pages a client can read.',
    expected: [
      e('Tampering', 'Injection through the filter string reaches the database', 'Critical', 'inject', 'template', 'filter', 'sql', 'query'),
      e('InformationDisclosure', 'Unlimited paging lets anyone scrape the whole catalogue', 'Medium', 'scrap', 'page', 'harvest'),
      e('DenialOfService', 'Expensive filters and deep paging overload the database', 'Medium', 'expensive', 'overload', 'exhaust', 'load'),
    ],
  },
  {
    id: 'fresh-mobile-01', domain: 'mobile', summary: 'Offline loyalty card with QR code',
    design: 'The mobile app shows a loyalty QR code that cashiers scan at the till to add points. The QR code holds the customer id and is generated on the phone, so it works offline. Points can be swapped for free products in the app.',
    expected: [
      e('Spoofing', 'Copied or forged QR code collects points on someone else’s account', 'High', 'qr', 'forge', 'copy', 'customer id', 'screenshot'),
      e('Tampering', 'Points redeemed twice while the phone is offline', 'Medium', 'offline', 'double', 'twice', 'replay'),
    ],
  },
  {
    id: 'fresh-mobile-02', domain: 'mobile', summary: 'In-app chat with image sharing',
    design: 'Users of the marketplace app can chat with sellers and send photos. Photos are uploaded to our server and shown in the other person’s chat. The app keeps the full chat history on the phone in a local database. Anyone can create a seller account.',
    expected: [
      e('Spoofing', 'Fake sellers use chat to phish buyers off the platform', 'Medium', 'phish', 'fake seller', 'scam', 'off-platform', 'fraud'),
      e('InformationDisclosure', 'Chat history readable from the phone’s local database', 'Medium', 'local', 'database', 'device', 'unencrypted', 'backup'),
      e('InformationDisclosure', 'Photo location metadata reveals where users live', 'Low', 'metadata', 'exif', 'location', 'gps'),
    ],
  },
  {
    id: 'fresh-data-01', domain: 'data', summary: 'Customer CSV import into the CRM',
    design: 'Sales staff upload customer lists as CSV files. A nightly job loads each file into the CRM database and emails the uploader a summary. Rows from the CSV are written straight into the customers table. The CRM can export customers back to CSV for the marketing team.',
    expected: [
      e('Tampering', 'Imported rows overwrite or corrupt existing customer records', 'Medium', 'overwrite', 'corrupt', 'existing', 'validation'),
      e('Tampering', 'Formula injection in exported CSV runs on marketing machines', 'Medium', 'formula', 'csv injection', 'excel'),
      e('Repudiation', 'No record of who imported which rows', 'Low', 'audit', 'record', 'uploader', 'trace'),
    ],
  },
  {
    id: 'fresh-data-02', domain: 'data', summary: 'Shared analytics dashboards with row-level data',
    design: 'Analysts build dashboards on top of the data warehouse and can share a dashboard by link with anyone in the company. Dashboards query the warehouse with the analyst’s credentials, which include salary and health-plan tables. Shared links never expire.',
    expected: [
      e('InformationDisclosure', 'Shared dashboard shows salary and health data to anyone with the link', 'High', 'link', 'salary', 'health', 'credentials', 'share'),
      e('ElevationOfPrivilege', 'Viewers inherit the analyst’s warehouse permissions', 'High', 'credential', 'permission', 'inherit', 'analyst'),
      e('InformationDisclosure', 'Links that never expire keep working after people leave', 'Medium', 'expire', 'revoke', 'leave'),
    ],
  },
  {
    id: 'fresh-ai-01', domain: 'ai', summary: 'AI assistant that books meetings from email',
    design: 'An assistant reads each employee’s inbox and calendar. When an email asks for a meeting, it books a slot, sends invites to the people named in the email and can attach files from the employee’s drive that the email mentions. It acts without asking the employee first.',
    expected: [
      e('ElevationOfPrivilege', 'Email from outside hijacks the assistant', 'High', 'inject', 'hijack', 'malicious email', 'instruction'),
      e('InformationDisclosure', 'Assistant attaches drive files for an outside sender', 'High', 'attach', 'drive', 'exfiltrat', 'file'),
      e('Spoofing', 'Invites sent in the employee’s name to people the attacker chooses', 'Medium', 'invite', 'name', 'phish', 'impersonat'),
    ],
  },
  {
    id: 'fresh-ai-02', domain: 'ai', summary: 'Code review bot that comments on pull requests',
    design: 'A bot reviews every pull request with an LLM and posts comments. It reads the diff and the repository’s files, and it can approve pull requests when it finds no issues. Pull requests can come from forks by anyone on the internet. The bot’s token can approve and merge.',
    expected: [
      e('Tampering', 'Instructions hidden in a pull request make the bot approve malicious code', 'Critical', 'inject', 'approve', 'instruction', 'malicious'),
      e('ElevationOfPrivilege', 'Bot token with merge rights is the real gate', 'High', 'token', 'merge', 'privilege'),
      e('InformationDisclosure', 'Bot leaks repository secrets into public comments', 'Medium', 'secret', 'leak', 'comment'),
    ],
  },
];
