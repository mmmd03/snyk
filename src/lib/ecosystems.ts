import * as cppPlugin from 'snyk-cpp-plugin';
import * as dockerPlugin from 'snyk-docker-plugin';
import { DepGraphData, DepGraph } from '@snyk/dep-graph';
import { InspectResult } from '@snyk/cli-interface/legacy/plugin';
import chalk from 'chalk';

import * as snyk from './index';
import * as config from './config';
import { isCI } from './is-ci';
import { makeRequest } from './request/promise';
import { MonitorMeta, MonitorOptions, Options, PolicyOptions } from './types';
import { TestCommandResult } from '../cli/commands/types';
import * as spinner from '../lib/spinner';
import { formatMonitorOutput } from '../cli/commands/monitor/formatters/format-monitor-response';
import { GoodResult, BadResult } from '../cli/commands/monitor/types';
import { MonitorError } from './errors';
import { getExtraProjectCount } from './plugins/get-extra-project-count';
import { getInfo } from './project-metadata';

const SEPARATOR = '\n-------------------------------------------------------\n';

export interface Artifact {
  type: string;
  data: any;
  meta: { [key: string]: any };
}

export interface ScanResult {
  artifacts: Artifact[];
  meta: {
    [key: string]: any;
  };
}

export interface Issue {
  pkgName: string;
  pkgVersion?: string;
  issueId: string;
  fixInfo: {
    nearestFixedInVersion?: string;
  };
}

export interface IssuesData {
  [issueId: string]: {
    id: string;
    severity: string;
    title: string;
  };
}

export interface TestResult {
  issues: Issue[];
  issuesData: IssuesData;
  depGraphData: DepGraphData;
}

export interface EcosystemMonitorError {
  error: string;
  path: string;
}

export interface EcosystemMonitorResult {
  ok: boolean;
  org: string;
  id: string;
  isMonitored: boolean;
  licensesPolicy: any;
  uri: string;
  trialStarted: boolean;
  path: string;
  projectName: string;
  projectType: string;
}

export interface EcosystemPlugin {
  scan: (
    root: string,
    targetFile?: string,
    options?: Options,
  ) => Promise<ScanResult[]>;
  display: (
    scanResults: ScanResult[],
    testResults: TestResult[],
    errors: string[],
    options: Options,
  ) => Promise<string>;
}

export type Ecosystem = 'cpp' | 'docker';

const EcosystemPlugins: {
  readonly [ecosystem in Ecosystem]: EcosystemPlugin;
} = {
  cpp: cppPlugin as any, // TODO
  docker: dockerPlugin as any, // TODO
};

export function getPlugin(ecosystem: Ecosystem): EcosystemPlugin {
  return EcosystemPlugins[ecosystem];
}

export function getEcosystem(options: Options): Ecosystem | null {
  if (options.source) {
    return 'cpp';
  }
  if (options.docker) {
    return 'docker';
  }
  return null;
}

export async function testEcosystem(
  ecosystem: Ecosystem,
  paths: string[],
  options: Options,
): Promise<TestCommandResult> {
  const plugin = getPlugin(ecosystem);
  const scanResultsByPath: { [dir: string]: ScanResult[] } = {};
  for (const path of paths) {
    options.path = path;
    // TODO
    const results = await plugin.scan('', undefined, options);
    scanResultsByPath[path] = results;
  }
  const [testResults, errors] = await testDependencies(scanResultsByPath);
  const stringifiedData = JSON.stringify(testResults, null, 2);
  if (options.json) {
    return TestCommandResult.createJsonTestCommandResult(stringifiedData);
  }
  const emptyResults: ScanResult[] = [];
  const scanResults = emptyResults.concat(...Object.values(scanResultsByPath));
  const readableResult = await plugin.display(
    scanResults,
    testResults,
    errors,
    options,
  );

  return TestCommandResult.createHumanReadableTestCommandResult(
    readableResult,
    stringifiedData,
  );
}

export async function testDependencies(scans: {
  [dir: string]: ScanResult[];
}): Promise<[TestResult[], string[]]> {
  const results: TestResult[] = [];
  const errors: string[] = [];
  for (const [path, scanResults] of Object.entries(scans)) {
    await spinner(`Testing dependencies in ${path}`);
    for (const scanResult of scanResults) {
      const payload = {
        method: 'POST',
        url: `${config.API}/test-dependencies`,
        json: true,
        headers: {
          'x-is-ci': isCI(),
          authorization: 'token ' + snyk.api,
        },
        body: {
          ...scanResult,
        },
      };
      try {
        const response = await makeRequest<TestResult>(payload);
        results.push(response);
      } catch (error) {
        if (error.code >= 400 && error.code < 500) {
          throw new Error(error.message);
        }
        errors.push('Could not test dependencies in ' + path);
      }
    }
  }
  spinner.clearAll();
  return [results, errors];
}

export async function monitorEcosystem(
  ecosystem: Ecosystem,
  paths: string[],
  options: Options,
): Promise<[EcosystemMonitorResult[], EcosystemMonitorError[]]> {
  const plugin = getPlugin(ecosystem);
  const scanResultsByPath: { [dir: string]: ScanResult[] } = {};
  for (const path of paths) {
    options.path = path;
    // TODO: What if this throws?
    const results = await plugin.scan(path, undefined, options);
    scanResultsByPath[path] = results;
  }
  const [monitorResults, errors] = await monitorDependencies(
    scanResultsByPath,
    options,
  );
  return [monitorResults, errors];
}

function generateMonitorMeta(options, packageManager?): MonitorMeta {
  return {
    method: 'cli',
    packageManager,
    'policy-path': options['policy-path'],
    'project-name': options['project-name'] || config.PROJECT_NAME,
    isDocker: !!options.docker,
    prune: !!options.pruneRepeatedSubdependencies,
    'experimental-dep-graph': !!options['experimental-dep-graph'],
    'remote-repo-url': options['remote-repo-url'],
  };
}

/**
 * Some artifacts like the DepGraph get auto-serialized when transmitted as JSON over the wire.
 * We want to avoid surprises here, otherwise we send a payload and it gets mutated at the receiving end.
 * Here we are explicit - where necessary we will convert an artifact from one type to another.
 * The receiving end (Registry) would take care of mapping back to a deserialized Artifact.
 */
function serializeArtifacts(artifacts: Artifact[]): Artifact[] {
  return artifacts.map((artifact) => {
    if (artifact.type === 'depGraph') {
      return {
        type: 'depGraphData',
        meta: artifact.meta,
        data: (artifact.data as DepGraph).toJSON(),
      };
    }

    return artifact;
  });
}

export async function monitorDependencies(
  scans: {
    [dir: string]: ScanResult[];
  },
  options: Options,
): Promise<[EcosystemMonitorResult[], EcosystemMonitorError[]]> {
  const results: EcosystemMonitorResult[] = [];
  const errors: EcosystemMonitorError[] = [];
  for (const [path, scanResults] of Object.entries(scans)) {
    await spinner(`Testing dependencies in ${path}`);
    for (const scanResult of scanResults) {
      const target = await getInfo(scanResult, generateMonitorMeta(options));

      const serializedArtifacts = serializeArtifacts(scanResult.artifacts);
      const scanResultWithSerializedArtifacts: ScanResult = {
        ...scanResult,
        artifacts: serializedArtifacts,
      };

      const payload = {
        method: 'PUT',
        url: `${config.API}/monitor-dependencies`,
        json: true,
        headers: {
          'x-is-ci': isCI(),
          authorization: 'token ' + snyk.api,
        },
        body: {
          scanResult: scanResultWithSerializedArtifacts,
          target,
        },
      };
      try {
        const response = await makeRequest<EcosystemMonitorResult>(payload);
        results.push({
          ...response,
          path,
        });
      } catch (error) {
        if (error.code >= 400 && error.code < 500) {
          throw new Error(error.message);
        }
        errors.push({
          error: 'Could not monitor dependencies in ' + path,
          path,
        });
      }
    }
  }
  spinner.clearAll();
  return [results, errors];
}

export async function getFormattedMonitorOutput(
  results: Array<GoodResult | BadResult>,
  monitorResults: EcosystemMonitorResult[],
  errors: EcosystemMonitorError[],
  options: Options & MonitorOptions & PolicyOptions,
): Promise<string> {
  for (const monitorResult of monitorResults) {
    const monOutput = formatMonitorOutput(
      monitorResult.projectType,
      monitorResult as any,
      options,
      monitorResult.projectName,
      await getExtraProjectCount(
        monitorResult.path,
        options,
        {} as InspectResult,
      ),
    );
    results.push({
      ok: true,
      data: monOutput,
      path: monitorResult.path,
      projectName: monitorResult.id,
    });
  }
  for (const monitorError of errors) {
    results.push({
      ok: false,
      data: new MonitorError(500, monitorError),
      path: monitorError.path,
    });
  }

  const outputString = results
    .map((res) => {
      if (res.ok) {
        return res.data;
      }

      const errorMessage =
        res.data && res.data.userMessage
          ? chalk.bold.red(res.data.userMessage)
          : res.data
          ? res.data.message
          : 'Unknown error occurred.';

      return (
        chalk.bold.white('\nMonitoring ' + res.path + '...\n\n') + errorMessage
      );
    })
    .join('\n' + SEPARATOR);

  if (results.every((res) => res.ok)) {
    return outputString;
  }

  throw new Error(outputString);
}
