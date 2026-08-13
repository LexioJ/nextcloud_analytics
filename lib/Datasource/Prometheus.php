<?php
/**
 * Analytics
 *
 * SPDX-FileCopyrightText: 2026 Marcel Scherello
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Analytics\Datasource;

use OCA\Analytics\Security\ExternalHttpClient;
use OCA\Analytics\Security\ExternalUrlValidator;
use OCP\IAppConfig;
use OCP\IL10N;
use Psr\Log\LoggerInterface;

/**
 * Reads metrics from any endpoint using the Prometheus text exposition format.
 *
 * A dedicated Prometheus server is not required. Combined with a scheduled data load and the
 * "timestamp" option, every run appends a new row and the dataset becomes a time series.
 */
class Prometheus implements IDatasource, IReportTemplateProvider {
	private const CACHE_TTL_SECONDS = 30;
	/** dimension1 of analytics_facts is limited to 64 characters */
	private const MAX_KEY_LENGTH = 64;
	/** guard against unbounded label cardinality flooding the dataset */
	private const MAX_SERIES = 1000;
	/** stripped from the series key to save characters, all signaling metrics carry it */
	private const METRIC_PREFIX = 'signaling_';
	private const APP_CONFIG_TRUSTED_HOSTS = 'trustedMetricsHosts';

	public function __construct(
		private IL10N $l10n,
		private LoggerInterface $logger,
		private ExternalHttpClient $httpClient,
		private IAppConfig $appConfig,
	) {
	}

	/**
	 * @return string Display Name of the data source
	 */
	public function getName(): string {
		return $this->l10n->t('External') . ': Prometheus';
	}

	/**
	 * @return int digit unique data source id
	 */
	public function getId(): int {
		return 9;
	}

	/**
	 * @return array available options of the data source
	 */
	public function getTemplate(): array {
		$template = array();
		$template[] = ['id' => 'url', 'name' => 'URL', 'placeholder' => 'https://signaling.example.com/metrics'];
		$template[] = ['id' => 'metrics', 'name' => $this->l10n->t('Metrics'), 'placeholder' => 'signaling_hub_rooms,signaling_hub_*'];
		$template[] = ['id' => 'labels', 'name' => $this->l10n->t('Labels for the series name'), 'placeholder' => 'clienttype,backend'];
		$template[] = ['id' => 'timestamp', 'name' => $this->l10n->t('Timestamp of data load'), 'placeholder' => 'true-' . $this->l10n->t('Yes') . '/false-' . $this->l10n->t('No'), 'type' => 'tf'];
		$template[] = ['id' => 'section', 'name' => $this->l10n->t('More options'), 'type' => 'section'];
		$template[] = ['id' => 'includeBuckets', 'name' => $this->l10n->t('Include histogram buckets'), 'placeholder' => 'false-' . $this->l10n->t('No') . '/true-' . $this->l10n->t('Yes'), 'type' => 'tf'];
		$template[] = ['id' => 'limit', 'name' => $this->l10n->t('Limit'), 'placeholder' => $this->l10n->t('Number of rows'), 'type' => 'number'];
		$template[] = ['id' => 'auth', 'name' => $this->l10n->t('Authentication'), 'placeholder' => 'User:Password'];
		$template[] = ['id' => 'customHeaders', 'name' => 'Custom headers', 'placeholder' => 'key: value,key: value'];
		return $template;
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	public function getReportTemplates(): array {
		return [
			'talk_active_rooms' => [
				'name' => 'Talk: active rooms and sessions',
				'report' => [
					'name' => 'Talk: active rooms and sessions',
					'subheader' => 'Current values of the Talk signaling server. Create a scheduled data load with "Timestamp of data load" to build a history.',
					'parent' => '0',
					'type' => 9,
					'dataset' => 0,
					'link' => '{"dataSourceType":"","url":"","metrics":"signaling_hub_rooms,signaling_hub_sessions","labels":"","timestamp":"false","includeBuckets":"false","limit":"","auth":"","customHeaders":""}',
					'visualization' => 'ct',
					'chart' => 'column',
					'dimension1' => 'Metric',
					'dimension2' => 'Metric',
					'value' => 'false',
				],
				'options' => [
					'chartoptions' => '{"__analytics_gui":{"version":2,"model":"kpiModel","doughnutLabelStyle":"percentage"}}',
					'dataoptions' => '[]',
					'filteroptions' => '{}',
					'tableoptions' => '{"order":[[0,"desc"]]}',
				],
			],
			'talk_sessions_by_clienttype' => [
				'name' => 'Talk: sessions by client type',
				'report' => [
					'name' => 'Talk: sessions by client type',
					'subheader' => 'Signaling sessions split by client type. Create a scheduled data load with "Timestamp of data load" to build a history.',
					'parent' => '0',
					'type' => 9,
					'dataset' => 0,
					'link' => '{"dataSourceType":"","url":"","metrics":"signaling_hub_sessions","labels":"clienttype","timestamp":"false","includeBuckets":"false","limit":"","auth":"","customHeaders":""}',
					'visualization' => 'ct',
					'chart' => 'column',
					'dimension1' => 'Metric',
					'dimension2' => 'Metric',
					'value' => 'false',
				],
				'options' => [
					'chartoptions' => '{"__analytics_gui":{"version":2,"model":"kpiModel","doughnutLabelStyle":"percentage"}}',
					'dataoptions' => '[]',
					'filteroptions' => '{}',
					'tableoptions' => '{"order":[[0,"desc"]]}',
				],
			],
			'talk_mcu_load' => [
				'name' => 'Talk: MCU publishers and subscribers',
				'report' => [
					'name' => 'Talk: MCU publishers and subscribers',
					'subheader' => 'Current media load of the Talk signaling server. Create a scheduled data load with "Timestamp of data load" to build a history.',
					'parent' => '0',
					'type' => 9,
					'dataset' => 0,
					'link' => '{"dataSourceType":"","url":"","metrics":"signaling_mcu_publishers,signaling_mcu_subscribers","labels":"type","timestamp":"false","includeBuckets":"false","limit":"","auth":"","customHeaders":""}',
					'visualization' => 'ct',
					'chart' => 'column',
					'dimension1' => 'Metric',
					'dimension2' => 'Metric',
					'value' => 'false',
				],
				'options' => [
					'chartoptions' => '{"__analytics_gui":{"version":2,"model":"kpiModel","doughnutLabelStyle":"percentage"}}',
					'dataoptions' => '[]',
					'filteroptions' => '{}',
					'tableoptions' => '{"order":[[0,"desc"]]}',
				],
			],
		];
	}

	/**
	 * Read the Data
	 * @param $option
	 * @return array available options of the data source
	 */
	public function readData($option): array {
		$cache = $this->getCacheMetadata($option);
		if ($cache['notModified'] === true) {
			return [
				'header' => [],
				'dimensions' => [],
				'data' => [],
				'rawdata' => null,
				'error' => 0,
				'cache' => $cache,
			];
		}

		$header = [$this->l10n->t('Metric'), $this->l10n->t('Value')];
		$url = htmlspecialchars_decode((string)($option['url'] ?? ''), ENT_NOQUOTES);
		$auth = (string)($option['auth'] ?? '');
		$headers = $this->parseHeaders(htmlspecialchars_decode((string)($option['customHeaders'] ?? ''), ENT_NOQUOTES));
		$headers['Accept'] = $headers['Accept'] ?? 'text/plain';
		$headers['User-Agent'] = 'Analytics for Nextcloud';

		$response = $this->httpClient->request(
			$url,
			'GET',
			$headers,
			null,
			$auth,
			$this->getTrustedHosts(),
		);

		if ($response['error'] !== null) {
			return [
				'header' => $header,
				'dimensions' => array_slice($header, 0, count($header) - 1),
				'data' => [],
				'error' => $response['error'],
				'cache' => $cache,
			];
		}

		$httpCode = $response['status'];
		if ($httpCode < 200 || $httpCode >= 300) {
			return [
				'header' => $header,
				'dimensions' => array_slice($header, 0, count($header) - 1),
				'data' => [],
				'error' => 'HTTP response code: ' . $httpCode,
				'cache' => $cache,
			];
		}

		return [
			'header' => $header,
			'dimensions' => array_slice($header, 0, count($header) - 1),
			'data' => $this->parseExposition($response['body'], $option),
			'rawdata' => $response['body'],
			'URL' => $url,
			'error' => 0,
			'cache' => $cache,
		];
	}

	/**
	 * Hosts an administrator explicitly trusts, so internal metrics endpoints can be reached.
	 * Metrics endpoints usually listen on a private address which the SSRF protection blocks by default.
	 *
	 * occ config:app:set analytics trustedMetricsHosts --value="signaling.internal:8080"
	 *
	 * @return string[]
	 */
	private function getTrustedHosts(): array {
		return ExternalUrlValidator::parseAllowedHosts(
			$this->appConfig->getValueString('analytics', self::APP_CONFIG_TRUSTED_HOSTS)
		);
	}

	/** @return array<string, string> */
	private function parseHeaders(string $customHeaders): array {
		$headers = [];
		foreach (explode(',', $customHeaders) as $header) {
			if (trim($header) === '') {
				continue;
			}
			[$name, $value] = array_pad(explode(':', $header, 2), 2, '');
			$headers[trim($name)] = trim($value);
		}
		return $headers;
	}

	private function getCacheMetadata($option): array {
		$currentCacheKey = 'prom-' . (string)floor(time() / self::CACHE_TTL_SECONDS);
		$clientCacheKey = isset($option['cacheKey']) ? trim((string)$option['cacheKey'], '"') : '';

		return [
			'cacheable' => true,
			'key' => $currentCacheKey,
			'notModified' => ($clientCacheKey !== '' && $clientCacheKey === $currentCacheKey),
		];
	}

	/**
	 * Turn the text exposition format into rows of [series name, value].
	 *
	 * Only two columns are returned on purpose: when the timestamp option is active, the controller
	 * shifts the rows to [series name, timestamp, value] and would drop any additional column.
	 *
	 * @return array<int, array{0: string, 1: float}>
	 */
	private function parseExposition(string $body, array $option): array {
		$metrics = $this->parseList(htmlspecialchars_decode((string)($option['metrics'] ?? ''), ENT_NOQUOTES));
		$keepLabels = $this->parseList(htmlspecialchars_decode((string)($option['labels'] ?? ''), ENT_NOQUOTES));
		$includeBuckets = ($option['includeBuckets'] ?? 'false') === 'true';

		$limit = isset($option['limit']) && (int)$option['limit'] > 0
			? min((int)$option['limit'], self::MAX_SERIES)
			: self::MAX_SERIES;

		$series = [];
		$truncated = false;

		foreach (preg_split('/\r\n|\r|\n/', $body) as $line) {
			$line = trim($line);
			if ($line === '' || $line[0] === '#') {
				continue;
			}

			$parsed = $this->parseLine($line);
			if ($parsed === null) {
				continue;
			}

			if (!$includeBuckets && str_ends_with($parsed['name'], '_bucket')) {
				continue;
			}
			if (!$this->metricMatches($parsed['name'], $metrics)) {
				continue;
			}

			$key = $this->buildSeriesKey($parsed['name'], $parsed['labels'], $keepLabels);

			// series collapsing onto the same key must be summed, otherwise they would produce
			// several rows sharing dimension1 and dimension2 and overwrite each other on storage
			if (isset($series[$key])) {
				$series[$key] += $parsed['value'];
				continue;
			}
			if (count($series) >= $limit) {
				$truncated = true;
				continue;
			}
			$series[$key] = $parsed['value'];
		}

		if ($truncated) {
			$this->logger->info('Analytics Prometheus data source truncated the result at ' . $limit . ' series');
		}

		$data = [];
		foreach ($series as $key => $value) {
			$data[] = [(string)$key, $value];
		}
		return $data;
	}

	/**
	 * Parse a single metric line into name, labels and value.
	 *
	 * @return array{name: string, labels: array<string, string>, value: float}|null
	 */
	private function parseLine(string $line): ?array {
		if (preg_match('/^[a-zA-Z_:][a-zA-Z0-9_:]*/', $line, $matches) !== 1) {
			return null;
		}
		$name = $matches[0];
		$rest = substr($line, strlen($name));
		$labels = [];

		if (isset($rest[0]) && $rest[0] === '{') {
			$end = $this->findLabelBlockEnd($rest);
			if ($end === null) {
				return null;
			}
			$labels = $this->parseLabels(substr($rest, 1, $end - 1));
			$rest = substr($rest, $end + 1);
		}

		$rest = trim($rest);
		if ($rest === '') {
			return null;
		}

		// the optional trailing exposition timestamp is ignored, the time axis comes from the data load
		$value = $this->parseValue((string)preg_split('/\s+/', $rest)[0]);
		if ($value === null) {
			return null;
		}

		return ['name' => $name, 'labels' => $labels, 'value' => $value];
	}

	/**
	 * Locate the closing brace of a label block. Label values are quoted and may contain
	 * braces and escaped quotes, so the block cannot be matched with a simple expression.
	 */
	private function findLabelBlockEnd(string $rest): ?int {
		$length = strlen($rest);
		$inQuotes = false;

		for ($i = 1; $i < $length; $i++) {
			$character = $rest[$i];
			if ($inQuotes) {
				if ($character === '\\') {
					$i++;
				} elseif ($character === '"') {
					$inQuotes = false;
				}
				continue;
			}
			if ($character === '"') {
				$inQuotes = true;
			} elseif ($character === '}') {
				return $i;
			}
		}

		return null;
	}

	/**
	 * @return array<string, string>
	 */
	private function parseLabels(string $labelBlock): array {
		$labels = [];
		preg_match_all('/([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\\\]|\\\\.)*)"/', $labelBlock, $matches, PREG_SET_ORDER);

		foreach ($matches as $match) {
			$labels[$match[1]] = $this->unescapeLabelValue($match[2]);
		}

		return $labels;
	}

	private function unescapeLabelValue(string $value): string {
		return preg_replace_callback('/\\\\(.)/', static function (array $match): string {
			return match ($match[1]) {
				'n' => "\n",
				default => $match[1],
			};
		}, $value) ?? $value;
	}

	/**
	 * NaN and the infinities are dropped instead of being stored as zero, which would distort charts.
	 */
	private function parseValue(string $raw): ?float {
		if (!is_numeric($raw)) {
			return null;
		}
		$value = (float)$raw;
		if (is_nan($value) || is_infinite($value)) {
			return null;
		}
		return $value;
	}

	/**
	 * An empty filter keeps every metric. A trailing asterisk matches by prefix.
	 * Histogram and summary parts of a selected metric are kept as well.
	 *
	 * @param string[] $patterns
	 */
	private function metricMatches(string $name, array $patterns): bool {
		if ($patterns === []) {
			return true;
		}

		foreach ($patterns as $pattern) {
			if (str_ends_with($pattern, '*')) {
				if (str_starts_with($name, substr($pattern, 0, -1))) {
					return true;
				}
				continue;
			}
			if ($name === $pattern) {
				return true;
			}
			foreach (['_sum', '_count', '_bucket'] as $suffix) {
				if ($name === $pattern . $suffix) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Build a series name that fits into dimension1. Overlong names are shortened with a
	 * checksum suffix so the key stays identical across runs and the time series stays connected.
	 *
	 * @param array<string, string> $labels
	 * @param string[] $keepLabels
	 */
	private function buildSeriesKey(string $name, array $labels, array $keepLabels): string {
		$key = str_starts_with($name, self::METRIC_PREFIX)
			? substr($name, strlen(self::METRIC_PREFIX))
			: $name;

		$values = [];
		foreach ($keepLabels as $label) {
			if (isset($labels[$label]) && $labels[$label] !== '') {
				$values[] = $labels[$label];
			}
		}
		if ($values !== []) {
			$key .= ' (' . implode(', ', $values) . ')';
		}

		if (mb_strlen($key) <= self::MAX_KEY_LENGTH) {
			return $key;
		}

		$suffix = '~' . substr(sprintf('%08x', crc32($key)), 0, 7);
		return mb_substr($key, 0, self::MAX_KEY_LENGTH - mb_strlen($suffix)) . $suffix;
	}

	/**
	 * @return string[]
	 */
	private function parseList(string $list): array {
		$entries = [];
		foreach (explode(',', $list) as $entry) {
			$entry = trim($entry);
			if ($entry !== '') {
				$entries[] = $entry;
			}
		}
		return $entries;
	}
}
