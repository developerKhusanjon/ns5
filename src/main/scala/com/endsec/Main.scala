package com.endsec

import cats.effect.*
import cats.syntax.all.*
import org.typelevel.log4cats.slf4j.Slf4jLogger
import org.typelevel.log4cats.Logger
import fs2.Stream

import com.endsec.services.*
import com.endsec.repositories.SecurityEventRepository
import com.endsec.api.EndSecApi
import com.endsec.cli.CommandLineInterface
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig
import io.github.resilience4j.retry.RetryConfig

import java.time.Duration
import scala.concurrent.duration.*

object Main extends IOApp.Simple:
  private val appName = "EndSec - Endpoint Security Monitor"
  private val appVersion = "1.0.0"

  def run: IO[Unit] =
    for
      logger <- Slf4jLogger.create[IO]
      _ <- logger.info(s"Starting $appName v$appVersion")

      // Initialize components
      repository <- SecurityEventRepository.inMemory[IO]
      virusScanService <- VirusScanService.make[IO](repository)
      vulnerabilityScanService <- VulnerabilityScanService.make[IO](repository)
      networkMonitorService <- NetworkMonitorService.make[IO](repository)

      // Create API server
      apiServer = EndSecApi.make[IO](
        repository,
        virusScanService,
        vulnerabilityScanService,
        networkMonitorService
      )

      // Create CLI
      cli = CommandLineInterface.make[IO](
        virusScanService,
        vulnerabilityScanService,
        networkMonitorService,
        repository,
        apiServer
      )

      // Run the application
      _ <- cli.run(appName, appVersion)
    yield ()