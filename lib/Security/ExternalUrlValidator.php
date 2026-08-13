<?php
/**
 * SPDX-FileCopyrightText: 2026 Marcel Scherello
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Analytics\Security;

class ExternalUrlValidator {
	/**
	 * @param string[] $allowedHosts hosts an administrator explicitly trusts, either as "host" or "host:port".
	 *                               A match only skips the private/reserved address check. All other
	 *                               restrictions stay in place.
	 */
	public static function validate(string $url, array $allowedHosts = []): ?string {
		$url = trim($url);
		if ($url === '') {
			return 'External URL is empty';
		}

		$parts = parse_url($url);
		if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
			return 'External URL is invalid';
		}
		if (isset($parts['user']) || isset($parts['pass'])) {
			return 'Credentials in external URLs are not allowed';
		}

		$scheme = strtolower((string)$parts['scheme']);
		if (!in_array($scheme, ['http', 'https'], true)) {
			return 'External URL scheme is not allowed';
		}

		$host = strtolower(rtrim((string)$parts['host'], '.'));
		if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
			$host = substr($host, 1, -1);
		}
		if ($host === '') {
			return 'External URL host is not allowed';
		}

		$isTrusted = self::isTrustedHost($host, $parts['port'] ?? null, $allowedHosts);

		if (!$isTrusted && ($host === 'localhost' || str_ends_with($host, '.localhost'))) {
			return 'External URL host is not allowed';
		}

		// trusted hosts are allowed to point to internal infrastructure, so the address check is skipped
		if ($isTrusted) {
			return null;
		}

		$addresses = self::resolveHost($host);
		if ($addresses === []) {
			return 'External URL host could not be resolved';
		}

		foreach ($addresses as $address) {
			if (!self::isPublicIp($address)) {
				return 'External URL resolves to a private or reserved address';
			}
		}

		return null;
	}

	/**
	 * @param string[] $allowedHosts
	 */
	public static function isAllowed(string $url, array $allowedHosts = []): bool {
		return self::validate($url, $allowedHosts) === null;
	}

	/**
	 * Parse an administrator maintained allow list into single entries.
	 *
	 * @return string[]
	 */
	public static function parseAllowedHosts(string $allowedHosts): array {
		$entries = [];
		foreach (explode(',', $allowedHosts) as $entry) {
			$entry = trim($entry);
			if ($entry !== '') {
				$entries[] = $entry;
			}
		}
		return $entries;
	}

	/**
	 * An entry without a port matches the host on any port. An entry with a port only matches that port.
	 *
	 * @param string[] $allowedHosts
	 */
	private static function isTrustedHost(string $host, $port, array $allowedHosts): bool {
		$port = ($port === null || $port === '') ? null : (int)$port;

		foreach ($allowedHosts as $allowedHost) {
			// parsing with a dummy scheme normalises "host", "host:port" and "[ipv6]:port" the same way the URL was parsed
			$parts = parse_url('http://' . trim($allowedHost));
			if (!is_array($parts) || !isset($parts['host'])) {
				continue;
			}

			$entryHost = strtolower(rtrim((string)$parts['host'], '.'));
			if (str_starts_with($entryHost, '[') && str_ends_with($entryHost, ']')) {
				$entryHost = substr($entryHost, 1, -1);
			}
			if ($entryHost !== $host) {
				continue;
			}

			if (!isset($parts['port']) || (int)$parts['port'] === $port) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @return string[]
	 */
	private static function resolveHost(string $host): array {
		if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
			return [$host];
		}

		$addresses = [];
		$ipv4 = @gethostbynamel($host);
		if (is_array($ipv4)) {
			$addresses = array_merge($addresses, $ipv4);
		}

		$ipv6 = @dns_get_record($host, DNS_AAAA);
		if (is_array($ipv6)) {
			foreach ($ipv6 as $record) {
				if (isset($record['ipv6'])) {
					$addresses[] = $record['ipv6'];
				}
			}
		}

		return array_values(array_unique($addresses));
	}

	private static function isPublicIp(string $address): bool {
		if (preg_match('/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $address, $matches)) {
			$address = $matches[1];
		}
		if (filter_var($address, FILTER_VALIDATE_IP) === false) {
			return false;
		}

		return filter_var(
			$address,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		) !== false;
	}
}
