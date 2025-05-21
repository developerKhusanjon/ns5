package com.endsec.cli

import cats.effect.*
import cats.syntax.all.*
import com.monovore.decline.*
import com.monovore.decline.effect.*
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import com.endsec.services.*
import com.endsec.repositories.SecurityEventRepository
import com.endsec.api.EndSecApi
import com.endsec.domain.*
import com.endsec.utils.OutputFormatter

import java.time.Instant
import java.time.format.DateTimeFormatter
import java.nio.file.{Path => JPath}
import fs2.io.file.Path

/** Command Line Interface for EndSec application */
trait CommandLineInterface[F[_]]:
  def run(appName: String, appVersion: String): F[Unit]

object CommandLineInterface:
  def make[F[_]: Async: Logger](
                                 virusScanService: VirusScanService[F],
                                 vulnerabilityScanService: VulnerabilityScanService[F],
                                 networkMonitorService: NetworkMonitorService[F],
                                 repository: SecurityEventRepository[F],
                                 apiServer: EndSecApi[F]
                               ): CommandLineInterface[F] =
    new CommandLineInterfaceImpl[F](
      virusScanService,
      vulnerabilityScanService,
      networkMonitorService,
      repository,
      apiServer
    )

private class CommandLineInterfaceImpl[F[_]: Async: Logger](
                                                             virusScanService: VirusScanService[F],
                                                             vulnerabilityScanService: VulnerabilityScanService[F],
                                                             networkMonitorService: NetworkMonitorService[F],
                                                             repository: SecurityEventRepository[F],
                                                             apiServer: EndSecApi[F]
                                                           ) extends CommandLineInterface[F]:
  private val formatter = OutputFormatter[F]

  // Define CLI options and commands
  private val scanFileOpt = Opts.option[String]("file", short = "f", help = "File to scan for viruses")
    .map(Path(_))

  private val scanDirOpt = Opts.option[String]("dir", short = "d", help = "Directory to scan for viruses")
    .map(Path(_))

  private val recursiveOpt = Opts.flag("recursive", short = "r", help = "Scan directories recursively").orFalse

  private val limitOpt = Opts.option[Int]("limit", short = "n", help = "Limit number of results")
    .withDefault(10)

  private val jsonFormatOpt = Opts.flag("json", help = "Output results in JSON format").orFalse

  private val apiPortOpt = Opts.option[Int]("port", short = "p", help = "Port for API server")
    .withDefault(8080)

  private val apiHostOpt = Opts.option[String]("host", help = "Host for API server")
    .withDefault("0.0.0.0")

  // Commands
  private val virusScanCommand = Command("virus-scan", "Scan for viruses") {
    (scanFileOpt, scanDirOpt, recursiveOpt, jsonFormatOpt).mapN {
      (file, dir, recursive, jsonFormat) =>
        ScanCommand.VirusScan(file, dir, recursive, jsonFormat)
    }
  }

  private val quickScanCommand = Command("quick-scan", "Perform a quick virus scan") {
    jsonFormatOpt.map(ScanCommand.QuickScan(_))
  }

  private val fullScanCommand = Command("full-scan", "Perform a full system scan") {
    jsonFormatOpt.map(ScanCommand.FullScan(_))
  }

  private val vulnScanCommand = Command("vuln-scan", "Scan for vulnerabilities") {
    jsonFormatOpt.map(ScanCommand.VulnerabilityScan(_))
  }

  private val networkMonitorCommand = Command("net-monitor", "Start network monitoring") {
    jsonFormatOpt.map(ScanCommand.NetworkMonitor(_))
  }

  private val statusCommand = Command("status", "Show system security status") {
    jsonFormatOpt.map(ScanCommand.Status(_))
  }

  private val recentEventsCommand = Command("events", "Show recent security events") {
    (limitOpt, jsonFormatOpt).mapN(ScanCommand.RecentEvents(_, _))
  }

  private val serverCommand = Command("server", "Start the API server") {
    (apiHostOpt, apiPortOpt).mapN(ScanCommand.StartServer(_, _))
  }

  private val rootCommand = Command("endsec", "Endpoint Security Scanner") {
    (virusScanCommand orElse quickScanCommand orElse fullScanCommand
      orElse vulnScanCommand orElse networkMonitorCommand
      orElse statusCommand orElse recentEventsCommand orElse serverCommand).orElse {
      Opts(ScanCommand.ShowHelp)
    }
  }

  def run(appName: String, appVersion: String): F[Unit] =
    CommandIOApp.run(
      rootCommand,
      args => executeCommand(args),
      helpFlag = true,
      version = appVersion
    )

  private def executeCommand(cmd: ScanCommand): F[ExitCode] =
    implicit val logger: Logger[F] = Slf4jLogger.getLogger[F]

    cmd match
      case ScanCommand.VirusScan(filePath, dirPath, recursive, jsonFormat) =>
        for
          _ <- Logger[F].info("Starting virus scan")
          result <- (filePath, dirPath) match
            case (Some(file), _) =>
              virusScanService.scanFile(file).flatMap {
                case Some(detection) =>
                  formatter.formatDetection(detection, jsonFormat) >>
                    ExitCode.Success.pure[F]
                case None =>
                  Logger[F].info(s"No viruses found in $file") >>
                    ExitCode.Success.pure[F]
              }
            case (_, Some(dir)) =>
              virusScanService.scanDirectory(dir, recursive)
                .evalTap(detection => formatter.formatDetection(detection, jsonFormat))
                .compile
                .count
                .flatMap { count =>
                  Logger[F].info(s"Scan complete. Found $count viruses.") >>
                    ExitCode.Success.pure[F]
                }
            case _ =>
              Logger[F].error("Either file or directory must be specified") >>
                ExitCode.Error.pure[F]
        yield result

      case ScanCommand.QuickScan(jsonFormat) =>
        for
          _ <- Logger[F].info("Starting quick scan")
          result <- virusScanService.quickScan
          _ <- formatter.formatScanResult(result, jsonFormat)
          _ <- Logger[F].info("Quick scan completed")
        yield ExitCode.Success

      case ScanCommand.FullScan(jsonFormat) =>
        for
          _ <- Logger[F].info("Starting full system scan")
          result <- virusScanService.fullSystemScan
          _ <- formatter.formatScanResult(result, jsonFormat)
          _ <- Logger[F].info("Full system scan completed")
        yield ExitCode.Success

      case ScanCommand.VulnerabilityScan(jsonFormat) =>
        for
          _ <- Logger[F].info("Starting vulnerability scan")
          result <- vulnerabilityScanService.scanSystem()
          _ <- formatter.formatScanResult(result, jsonFormat)
          _ <- Logger[F].info("Vulnerability scan completed")
        yield ExitCode.Success

      case ScanCommand.NetworkMonitor(jsonFormat) =>
        for
          _ <- Logger[F].info("Starting network monitoring")
          fiber <- networkMonitorService.startMonitoring
          _ <- Logger[F].info("Network monitoring started. Press Ctrl+C to stop.")
          // Keep the program running until interrupted
          _ <- Async[F].never
        yield ExitCode.Success

      case ScanCommand.Status(jsonFormat) =>
        for
          _ <- Logger[F].info("Getting system status")
          networkStatus <- networkMonitorService.getCurrentStatus
          _ <- formatter.formatNetworkStatus(networkStatus, jsonFormat)
        yield ExitCode.Success

      case ScanCommand.RecentEvents(limit, jsonFormat) =>
        for
          _ <- Logger[F].info(s"Getting recent security events (limit: $limit)")
          events <- repository.getRecent[SecurityEvent](limit)
          _ <- formatter.formatEvents(events, jsonFormat)
        yield ExitCode.Success

      case ScanCommand.StartServer(host, port) =>
        for
          _ <- Logger[F].info(s"Starting API server on $host:$port")
          _ <- apiServer.start(host, port)
        yield ExitCode.Success

      case ScanCommand.ShowHelp =>
        // The help message is automatically shown by Decline
        ExitCode.Success.pure[F]

/** Commands supported by the CLI */
sealed trait ScanCommand

object ScanCommand:
  case class VirusScan(
                        file: Option[Path],
                        dir: Option[Path],
                        recursive: Boolean,
                        jsonFormat: Boolean
                      ) extends ScanCommand

  case class QuickScan(jsonFormat: Boolean) extends ScanCommand

  case class FullScan(jsonFormat: Boolean) extends ScanCommand

  case class VulnerabilityScan(jsonFormat: Boolean) extends ScanCommand

  case class NetworkMonitor(jsonFormat: Boolean) extends ScanCommand

  case class Status(jsonFormat: Boolean) extends ScanCommand

  case class RecentEvents(limit: Int, jsonFormat: Boolean) extends ScanCommand

  case class StartServer(host: String, port: Int) extends ScanCommand

  case object ShowHelp extends ScanCommand