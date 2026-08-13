<?php
namespace OCA\Analytics\Tests\Datasource;

use OCA\Analytics\Datasource\Prometheus;
use OCA\Analytics\Security\ExternalHttpClient;
use OCA\Analytics\Tests\Stubs\FakeL10N;
use OCP\IAppConfig;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class PrometheusTest extends TestCase
{
	private Prometheus $prometheus;
	private $httpClient;

	protected function setUp(): void
	{
		$this->httpClient = $this->createMock(ExternalHttpClient::class);
		$this->prometheus = new Prometheus(
			new FakeL10N(),
			new NullLogger(),
			$this->httpClient,
			$this->createMock(IAppConfig::class)
		);
	}

	private function parse(string $body, array $option = []): array
	{
		$method = new \ReflectionMethod(Prometheus::class, 'parseExposition');
		$method->setAccessible(true);
		return $method->invoke($this->prometheus, $body, $option);
	}

	private function buildSeriesKey(string $name, array $labels, array $keepLabels): string
	{
		$method = new \ReflectionMethod(Prometheus::class, 'buildSeriesKey');
		$method->setAccessible(true);
		return $method->invoke($this->prometheus, $name, $labels, $keepLabels);
	}

	public function testParsesLabelledAndUnlabelledSeriesAndSkipsComments(): void
	{
		$body = <<<'METRICS'
# HELP signaling_hub_rooms Current number of rooms
# TYPE signaling_hub_rooms gauge
signaling_hub_rooms{backend="https://cloud.example.com/"} 3
# TYPE signaling_grpc_clients gauge
signaling_grpc_clients 2
METRICS;

		$this->assertSame(
			[
				['hub_rooms', 3.0],
				['grpc_clients', 2.0],
			],
			$this->parse($body)
		);
	}

	public function testKeepsSelectedLabelsInTheSeriesName(): void
	{
		$body = 'signaling_hub_sessions{backend="https://cloud.example.com/",clienttype="client"} 12';

		$this->assertSame(
			[['hub_sessions (client)', 12.0]],
			$this->parse($body, ['labels' => 'clienttype'])
		);
	}

	public function testSumsSeriesCollapsingOntoTheSameKey(): void
	{
		$body = <<<'METRICS'
signaling_hub_sessions{backend="https://a.example.com/",clienttype="client"} 4
signaling_hub_sessions{backend="https://b.example.com/",clienttype="client"} 6
METRICS;

		$this->assertSame(
			[['hub_sessions (client)', 10.0]],
			$this->parse($body, ['labels' => 'clienttype'])
		);
	}

	public function testParsesLabelValuesContainingBracesAndEscapes(): void
	{
		$body = 'signaling_backend_client_requests_errors_total{backend="a",error="oops \"}\" \\\\ done"} 7';

		$this->assertSame(
			[['backend_client_requests_errors_total (oops "}" \\ done)', 7.0]],
			$this->parse($body, ['labels' => 'error'])
		);
	}

	public function testDropsNanAndInfinityValues(): void
	{
		$body = <<<'METRICS'
signaling_mcu_backend_load{url="a"} NaN
signaling_mcu_backend_load{url="b"} +Inf
signaling_mcu_backend_load{url="c"} -Inf
signaling_mcu_backend_load{url="d"} 5
METRICS;

		$this->assertSame(
			[['mcu_backend_load (d)', 5.0]],
			$this->parse($body, ['labels' => 'url'])
		);
	}

	public function testWildcardFilterMatchesByPrefix(): void
	{
		$body = <<<'METRICS'
signaling_hub_rooms 3
signaling_hub_sessions 12
signaling_mcu_publishers 4
METRICS;

		$this->assertSame(
			[
				['hub_rooms', 3.0],
				['hub_sessions', 12.0],
			],
			$this->parse($body, ['metrics' => 'signaling_hub_*'])
		);
	}

	public function testExactFilterAlsoKeepsHistogramParts(): void
	{
		$body = <<<'METRICS'
signaling_client_rtt_bucket{le="0.005"} 42
signaling_client_rtt_sum 1234.5
signaling_client_rtt_count 99
signaling_hub_rooms 3
METRICS;

		// buckets are skipped by default, sum and count are kept
		$this->assertSame(
			[
				['client_rtt_sum', 1234.5],
				['client_rtt_count', 99.0],
			],
			$this->parse($body, ['metrics' => 'signaling_client_rtt'])
		);
	}

	public function testBucketsAreIncludedWhenRequested(): void
	{
		$body = 'signaling_client_rtt_bucket{le="0.005"} 42';

		$this->assertSame(
			[['client_rtt_bucket (0.005)', 42.0]],
			$this->parse($body, ['metrics' => 'signaling_client_rtt', 'includeBuckets' => 'true', 'labels' => 'le'])
		);
	}

	public function testTrailingExpositionTimestampIsIgnored(): void
	{
		$body = 'signaling_hub_rooms 3 1712345678000';

		$this->assertSame([['hub_rooms', 3.0]], $this->parse($body));
	}

	public function testLimitCapsTheNumberOfSeries(): void
	{
		$body = <<<'METRICS'
signaling_hub_rooms 3
signaling_hub_sessions 12
signaling_mcu_publishers 4
METRICS;

		$this->assertSame(
			[
				['hub_rooms', 3.0],
				['hub_sessions', 12.0],
			],
			$this->parse($body, ['limit' => '2'])
		);
	}

	public function testSeriesKeyIsShortenedDeterministically(): void
	{
		$labels = ['room' => str_repeat('a', 90)];

		$key = $this->buildSeriesKey('signaling_room_sessions', $labels, ['room']);

		$this->assertSame(64, mb_strlen($key));
		$this->assertSame($key, $this->buildSeriesKey('signaling_room_sessions', $labels, ['room']));
		$this->assertStringContainsString('~', $key);
	}

	public function testShortSeriesKeyIsLeftUntouched(): void
	{
		$this->assertSame(
			'hub_sessions (client)',
			$this->buildSeriesKey('signaling_hub_sessions', ['clienttype' => 'client'], ['clienttype'])
		);
	}

	public function testReadDataReturnsErrorStringOnHttpError(): void
	{
		$this->httpClient->method('request')->willReturn([
			'status' => 403,
			'body' => '',
			'error' => null,
		]);

		$result = $this->prometheus->readData(['url' => 'https://signaling.example.com/metrics']);

		$this->assertSame('HTTP response code: 403', $result['error']);
		$this->assertSame([], $result['data']);
	}

	public function testReadDataPassesThroughTransportError(): void
	{
		$this->httpClient->method('request')->willReturn([
			'status' => 0,
			'body' => '',
			'error' => 'External URL resolves to a private or reserved address',
		]);

		$result = $this->prometheus->readData(['url' => 'http://10.1.2.3:8080/metrics']);

		$this->assertSame('External URL resolves to a private or reserved address', $result['error']);
		$this->assertSame([], $result['data']);
	}

	public function testReadDataReturnsTwoColumnsOnSuccess(): void
	{
		$this->httpClient->method('request')->willReturn([
			'status' => 200,
			'body' => "signaling_hub_rooms 3\n",
			'error' => null,
		]);

		$result = $this->prometheus->readData([
			'url' => 'https://signaling.example.com/metrics',
			'metrics' => 'signaling_hub_rooms',
		]);

		$this->assertSame(0, $result['error']);
		$this->assertSame(['Metric', 'Value'], $result['header']);
		$this->assertSame(['Metric'], $result['dimensions']);
		$this->assertSame([['hub_rooms', 3.0]], $result['data']);
	}
}
