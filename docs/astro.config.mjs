// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import starlightLinksValidator from 'starlight-links-validator';

// GitHub Pages project site: https://indspl0it.github.io/gspwn/
// `base` is what every internal link resolves against, so pages link by
// Starlight slug and never by a hardcoded absolute path.
export default defineConfig({
  site: 'https://indspl0it.github.io',
  base: '/gspwn',
  trailingSlash: 'always',
  integrations: [
    // Must precede starlight: it registers the markdown transform that turns
    // ```mermaid fences into rendered diagrams.
    mermaid({
      // autoTheme swaps mermaid's own light and dark themes with the site's
      // colour scheme. Only the type is overridden: a single colour palette
      // cannot serve both schemes, and mermaid's two are built for the
      // backgrounds they run on.
      autoTheme: true,
      enableLog: false,
      mermaidConfig: {
        flowchart: { curve: 'basis', useMaxWidth: true, padding: 10 },
        sequence: { useMaxWidth: true },
        state: { useMaxWidth: true },
        themeVariables: {
          fontFamily:
            "ui-monospace, SFMono-Regular, 'JetBrains Mono', Menlo, monospace",
          fontSize: '14px',
        },
      },
    }),
    starlight({
      title: 'gspwn',
      description:
        'An autonomous autoresearch agent that fuzzes the NVIDIA GPU kernel driver and the NVIDIA Container Toolkit.',
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      components: {
        // Dark by default when the reader has expressed no preference.
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      expressiveCode: {
        themes: ['github-dark-default', 'github-light'],
        styleOverrides: {
          borderRadius: '0.5rem',
          borderWidth: '1px',
          codeFontFamily:
            "ui-monospace, SFMono-Regular, 'JetBrains Mono', 'Cascadia Code', Menlo, Consolas, monospace",
          codeFontSize: '0.8125rem',
          codeLineHeight: '1.65',
        },
      },
      plugins: [starlightLinksValidator({ errorOnRelativeLinks: false })],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/Indspl0it/gspwn',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/Indspl0it/gspwn/edit/main/docs/',
      },
      lastUpdated: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'gspwn', slug: '' },
            { label: 'Concepts', slug: 'getting-started/concepts' },
            { label: 'Requirements', slug: 'getting-started/requirements' },
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Quickstart', slug: 'getting-started/quickstart' },
            { label: 'Your first campaign', slug: 'getting-started/first-campaign' },
          ],
        },
        {
          label: 'Knowledgebase',
          items: [
            { label: 'Overview', slug: 'knowledgebase' },
            { label: 'NVIDIA GPU stack', slug: 'knowledgebase/gpu-stack' },
            { label: 'Product lines', slug: 'knowledgebase/product-lines' },
            { label: 'Driver and toolkit versions', slug: 'knowledgebase/driver-versions' },
            { label: 'Installed stack', slug: 'knowledgebase/installed-stack' },
            { label: 'Telemetry', slug: 'knowledgebase/telemetry' },
            { label: 'Container admission path', slug: 'knowledgebase/container-admission' },
            { label: 'Container device access', slug: 'knowledgebase/container-device-access' },
            { label: 'Orchestration', slug: 'knowledgebase/orchestration' },
            { label: 'Partitioning modes', slug: 'knowledgebase/partitioning' },
            { label: 'Execution model', slug: 'knowledgebase/execution-model' },
            { label: 'Memory model', slug: 'knowledgebase/memory-model' },
            { label: 'Compilation pipeline', slug: 'knowledgebase/compilation' },
            { label: 'API split and contexts', slug: 'knowledgebase/api-split' },
            { label: 'Resource Manager object model', slug: 'knowledgebase/rm-object-model' },
            { label: 'RM control command surface', slug: 'knowledgebase/rm-control-surface' },
            { label: 'UVM subsystem', slug: 'knowledgebase/uvm' },
            { label: 'GSP offload', slug: 'knowledgebase/gsp-offload' },
            { label: 'Chip organisation', slug: 'knowledgebase/chip-organisation' },
            { label: 'Memory hierarchy', slug: 'knowledgebase/memory-hierarchy' },
            { label: 'Scheduling and preemption', slug: 'knowledgebase/scheduling' },
            { label: 'Interconnect', slug: 'knowledgebase/interconnect' },
            { label: 'Boot and firmware chain', slug: 'knowledgebase/boot-firmware' },
            { label: 'Prior vulnerabilities', slug: 'knowledgebase/prior-vulnerabilities' },
          ],
        },
        {
          label: 'Architecture',
          items: [
            { label: 'Overview', slug: 'architecture/overview' },
            { label: 'Threat model', slug: 'architecture/threat-model' },
            { label: 'Attack surface', slug: 'architecture/attack-surface' },
            { label: 'Scope and oracle', slug: 'architecture/scope-and-oracle' },
            { label: 'Execution model', slug: 'architecture/execution-model' },
            { label: 'Loops', slug: 'architecture/loops' },
            { label: 'Sub-agents', slug: 'architecture/sub-agents' },
            { label: 'Coverage and plateau', slug: 'architecture/coverage-and-plateau' },
            { label: 'Crash identity', slug: 'architecture/crash-identity' },
            { label: 'Impact and severity', slug: 'architecture/impact-and-severity' },
            { label: 'Spend accounting', slug: 'architecture/spend-accounting' },
            { label: 'Durability', slug: 'architecture/durability' },
            { label: 'Data flow', slug: 'architecture/data-flow' },
            { label: 'Cloud deployment', slug: 'architecture/cloud-deployment' },
            { label: 'Extending gspwn', slug: 'architecture/extending' },
            {
              label: 'Components',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'architecture/components' },
                { label: 'pipeline_state.py', slug: 'architecture/components/pipeline-state' },
                { label: 'pipeline_ctl.py', slug: 'architecture/components/pipeline-ctl' },
                { label: 'gspwn_config.py', slug: 'architecture/components/gspwn-config' },
                { label: 'campaign_ctl.py', slug: 'architecture/components/campaign-ctl' },
                { label: 'coverage_ctl.py', slug: 'architecture/components/coverage-ctl' },
                { label: 'crash_parse.py', slug: 'architecture/components/crash-parse' },
                { label: 'crashlog_ctl.py', slug: 'architecture/components/crashlog-ctl' },
                { label: 'repro_ctl.py', slug: 'architecture/components/repro-ctl' },
                { label: 'orchestrator_ctl.py', slug: 'architecture/components/orchestrator-ctl' },
                { label: 'corpus_ctl.py', slug: 'architecture/components/corpus-ctl' },
                { label: 'knowledge_ctl.py', slug: 'architecture/components/knowledge-ctl' },
                { label: 'trace2seed.py', slug: 'architecture/components/trace2seed' },
                { label: 'ioctl_inventory.py', slug: 'architecture/components/ioctl-inventory' },
                { label: 'ctrl_surface.py', slug: 'architecture/components/ctrl-surface' },
                { label: 'object_graph.py', slug: 'architecture/components/object-graph' },
                { label: 'exec.py', slug: 'architecture/components/exec' },
                { label: 'build_kernel.sh', slug: 'architecture/components/build-kernel' },
                { label: 'selftest.py', slug: 'architecture/components/selftest' },
              ],
            },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Configuration keys', slug: 'reference/configuration' },
            {
              label: 'Command line',
              items: [
                { label: 'Overview', slug: 'reference/cli' },
                { label: 'pipeline_ctl.py', slug: 'reference/cli/pipeline-ctl' },
                { label: 'campaign_ctl.py', slug: 'reference/cli/campaign-ctl' },
                { label: 'coverage_ctl.py', slug: 'reference/cli/coverage-ctl' },
                { label: 'crash_parse.py', slug: 'reference/cli/crash-parse' },
                { label: 'crashlog_ctl.py', slug: 'reference/cli/crashlog-ctl' },
                { label: 'repro_ctl.py', slug: 'reference/cli/repro-ctl' },
                { label: 'orchestrator_ctl.py', slug: 'reference/cli/orchestrator-ctl' },
                { label: 'corpus_ctl.py', slug: 'reference/cli/corpus-ctl' },
                { label: 'knowledge_ctl.py', slug: 'reference/cli/knowledge-ctl' },
                { label: 'trace2seed.py', slug: 'reference/cli/trace2seed' },
                { label: 'gspwn_config.py', slug: 'reference/cli/gspwn-config' },
                { label: 'exec.py', slug: 'reference/cli/exec' },
                { label: 'build_kernel.sh', slug: 'reference/cli/build-kernel' },
                { label: 'selftest.py', slug: 'reference/cli/selftest' },
              ],
            },
            { label: 'State file schema', slug: 'reference/state-file' },
            { label: 'Closed vocabularies', slug: 'reference/vocabularies' },
            { label: 'Artifacts', slug: 'reference/artifacts' },
            { label: 'systemd units', slug: 'reference/systemd-units' },
            { label: 'Environment variables', slug: 'reference/environment' },
            { label: 'Exit codes', slug: 'reference/exit-codes' },
            { label: 'Xid classification', slug: 'reference/xid-classification' },
            { label: 'Sub-agents', slug: 'reference/sub-agents' },
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Running a campaign', slug: 'guides/running-a-campaign' },
            { label: 'Scope and targets', slug: 'guides/scope-and-targets' },
            { label: 'Configuration', slug: 'guides/configuration' },
            { label: 'Corpus and seeds', slug: 'guides/corpus-and-seeds' },
            { label: 'Seeds from traces', slug: 'guides/generating-seeds-from-traces' },
            { label: 'Results and triage', slug: 'guides/results-and-triage' },
            { label: 'Reproducing a crash', slug: 'guides/reproducing-a-crash' },
            { label: 'Long-running campaigns', slug: 'guides/long-running-campaigns' },
            { label: 'Unattended operation', slug: 'guides/unattended-operation' },
            { label: 'Budget and spend', slug: 'guides/budget-and-spend' },
            { label: 'Throughput against depth', slug: 'guides/tuning-throughput-vs-depth' },
            { label: 'Steering the next round', slug: 'guides/steering-the-next-round' },
            { label: 'Disk and crash logs', slug: 'guides/disk-and-crash-logs' },
            { label: 'Cloud runbook', slug: 'guides/cloud-runbook' },
            { label: 'Troubleshooting', slug: 'guides/troubleshooting' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Contributing', slug: 'project/contributing' },
            { label: 'Development', slug: 'project/development' },
            { label: 'Security and disclosure', slug: 'project/security' },
            { label: 'Rules of engagement', slug: 'project/rules-of-engagement' },
            { label: 'Changelog', slug: 'project/changelog' },
            { label: 'FAQ', slug: 'project/faq' },
            { label: 'License', slug: 'project/license' },
          ],
        },
      ],
    }),
  ],
});
