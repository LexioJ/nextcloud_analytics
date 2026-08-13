<?php
/**
 * Analytics
 *
 * SPDX-FileCopyrightText: 2026 Marcel Scherello
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Analytics\BackgroundJob;

use OCA\Analytics\Service\DataloadService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use Psr\Log\LoggerInterface;

class EveryFiveMinutes extends TimedJob
{

    private $logger;
    private $DataloadService;

    public function __construct(
        ITimeFactory $time,
        LoggerInterface $logger,
        DataloadService $DataloadService
    )
    {
        parent::__construct($time);
        $this->setInterval((60 * 5) - 60); // 1 minute because exact times would drift to the next cron execution
        $this->logger = $logger;
        $this->DataloadService = $DataloadService;
    }

    public function run($arguments)
    {
        try {
            $this->DataloadService->executeBySchedule('5');
        } catch (\Exception $e) {
            // no action
        }
    }

}
