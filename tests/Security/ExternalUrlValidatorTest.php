<?php
/**
 * SPDX-FileCopyrightText: 2026 Marcel Scherello
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Analytics\Tests\Security;

use OCA\Analytics\Security\ExternalUrlValidator;
use PHPUnit\Framework\TestCase;

class ExternalUrlValidatorTest extends TestCase {
	/**
	 * @dataProvider blockedUrls
	 */
	public function testValidateRejectsPrivateAndReservedTargets(string $url): void {
		$this->assertNotNull(ExternalUrlValidator::validate($url));
	}

	public function blockedUrls(): array {
		return [
			'localhost' => ['http://localhost/status'],
			'loopback' => ['http://127.0.0.1/status'],
			'private ipv4' => ['http://192.168.1.10/status'],
			'link local' => ['http://169.254.169.254/latest/meta-data'],
			'ipv6 loopback' => ['http://[::1]/status'],
			'ipv4-mapped ipv6 loopback' => ['http://[::ffff:127.0.0.1]/status'],
			'ipv4-mapped ipv6 metadata' => ['http://[::ffff:169.254.169.254]/latest/meta-data'],
			'userinfo' => ['https://user:password@example.com/data'],
			'file scheme' => ['file:///etc/passwd'],
		];
	}

	/**
	 * @dataProvider blockedUrls
	 */
	public function testEmptyAllowListKeepsPreviousBehaviour(string $url): void {
		$this->assertNotNull(ExternalUrlValidator::validate($url, []));
	}

	public function testPrivateAddressIsAcceptedWhenHostAndPortAreAllowed(): void {
		$this->assertNull(
			ExternalUrlValidator::validate('http://10.1.2.3:8080/metrics', ['10.1.2.3:8080'])
		);
	}

	public function testAllowListEntryWithoutPortMatchesAnyPort(): void {
		$this->assertNull(
			ExternalUrlValidator::validate('http://10.1.2.3:8080/metrics', ['10.1.2.3'])
		);
	}

	public function testAllowListEntryWithPortDoesNotMatchAnotherPort(): void {
		$this->assertSame(
			'External URL resolves to a private or reserved address',
			ExternalUrlValidator::validate('http://10.1.2.3:9090/metrics', ['10.1.2.3:8080'])
		);
	}

	public function testDifferentHostIsStillRejected(): void {
		$this->assertSame(
			'External URL resolves to a private or reserved address',
			ExternalUrlValidator::validate('http://10.9.9.9:8080/metrics', ['10.1.2.3:8080'])
		);
	}

	public function testLocalhostIsAcceptedOnlyWhenAllowed(): void {
		$this->assertSame(
			'External URL host is not allowed',
			ExternalUrlValidator::validate('http://localhost:8080/metrics')
		);
		$this->assertNull(
			ExternalUrlValidator::validate('http://localhost:8080/metrics', ['localhost:8080'])
		);
	}

	public function testAllowListDoesNotWeakenTheOtherChecks(): void {
		$this->assertSame(
			'Credentials in external URLs are not allowed',
			ExternalUrlValidator::validate('http://user:pass@10.1.2.3:8080/metrics', ['10.1.2.3:8080'])
		);
		$this->assertSame(
			'External URL scheme is not allowed',
			ExternalUrlValidator::validate('file://10.1.2.3/metrics', ['10.1.2.3'])
		);
	}

	public function testAllowListMatchingIsCaseInsensitive(): void {
		$this->assertNull(
			ExternalUrlValidator::validate('http://Signaling.Internal:8080/metrics', ['signaling.internal:8080'])
		);
	}

	public function testIpv6EntryIsMatched(): void {
		$this->assertNull(
			ExternalUrlValidator::validate('http://[fd00::1]:8080/metrics', ['[fd00::1]:8080'])
		);
	}

	public function testParseAllowedHostsTrimsAndDropsEmptyEntries(): void {
		$this->assertSame(
			['signaling.internal:8080', '10.1.2.3'],
			ExternalUrlValidator::parseAllowedHosts(' signaling.internal:8080 , ,10.1.2.3, ')
		);
	}

	public function testParseAllowedHostsReturnsEmptyArrayForEmptyInput(): void {
		$this->assertSame([], ExternalUrlValidator::parseAllowedHosts(''));
	}
}
