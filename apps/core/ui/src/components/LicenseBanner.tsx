import SectionMessage from '@atlaskit/section-message';

/** Paid via Atlassian: shown on the panel and the admin page while the site's license is inactive (docs/LICENSING.md). */
export function LicenseBanner() {
  return (
    <SectionMessage appearance="warning" title="Threatline's license for this site is inactive">
      Threatline starts no new reviews until the subscription is renewed. Existing reviews, requirements and the risk ledger stay readable, merge attestations for finished reviews are
      still issued, and the Done gate does not block. A site admin can renew Threatline in Atlassian Administration.
    </SectionMessage>
  );
}
