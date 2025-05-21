package com.endsec.services

import cats.effect.*
import cats.syntax.all.*
import fs2.Stream
import cats.effect.std.Queue
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import scala.concurrent.duration.*
import java.util.concurrent.TimeUnit
import java.time.Instant

import com.endsec.domain.*
import com.endsec.api.{DataCenterClient, ReportingResult}
import com.endsec.repositories.SecurityEventRepository

/** Service for reporting security events to the data center */
trait ReportingService[F[_]]:
  /** Report a single security event to the data center */
  def reportEvent[A <: SecurityEvent](event: A): F[ReportingResult]

  /** Report multiple security events to the data center */
  def reportEvents[A <: SecurityEvent](events: List[A]): F[ReportingResult]

  /** Report a scan result to the data center */
  def reportScanResult[A <: SecurityEvent](result: ScanResult[A]): F[ReportingResult]

  /** Start background reporting of events */
  def startBackgroundReporting: F[Fiber[F, Throwable, Unit]]

  /** Queue an event for background reporting */
  def queueEvent[A <: SecurityEvent](event: A): F[Unit]

  /** Get the current reporting service status */
  def getStatus: F[ReportingServiceStatus]

object ReportingService:
  /** Create a new reporting service */
  def make[F[_]: Async: Logger](
                                 client: DataCenterClient[F],
                                 repository: SecurityEventRepository[F],
                                 batchSize: Int = 50,
                                 reportingInterval: FiniteDuration = 5.minutes
                               ): F[ReportingService[F]] =
    for
      queue <- Queue.bounded[F, SecurityEvent](1000)
      serviceSyncRef <- Ref.of[F, Map[String, Instant]](Map.empty)
      lastSuccessfulReportRef <- Ref.of[F, Option[Instant]](None)
      failedReportsCountRef <- Ref.of[F, Int](0)
      reportingService = new ReportingServiceImpl[F](
        client,
        repository,
        queue,
        serviceSyncRef,
        lastSuccessfulReportRef,
        failedReportsCountRef,
        batchSize,
        reportingInterval
      )
    yield reportingService

private class ReportingServiceImpl[F[_]: Async: Logger](
                                                         client: DataCenterClient[F],
                                                         repository: SecurityEventRepository[F],
                                                         queue: Queue[F, SecurityEvent],
                                                         serviceSyncRef: Ref[F, Map[String, Instant]],  // Keep track of events we've reported
                                                         lastSuccessfulReportRef: Ref[F, Option[Instant]],
                                                         failedReportsCountRef: Ref[F, Int],
                                                         batchSize: Int,
                                                         reportingInterval: FiniteDuration
                                                       ) extends ReportingService[F]:

  private val logger = Slf4jLogger.getLogger[F]

  override def reportEvent[A <: SecurityEvent](event: A): F[ReportingResult] =
    for
      _ <- logger.info(s"Reporting event ${event.id} to data center")
      _ <- repository.save(event)  // Make sure it's saved locally
      result <- client.reportEvent(event)
      _ <- updateReportingStatus(result)
    yield result

  override def reportEvents[A <: SecurityEvent](events: List[A]): F[ReportingResult] =
    for
      _ <- logger.info(s"Reporting ${events.size} events to data center")
      _ <- events.traverse(repository.save)  // Save all events locally
      result <- client.reportEvents(events)
      _ <- updateReportingStatus(result)
    yield result

  override def reportScanResult[A <: SecurityEvent](result: ScanResult[A]): F[ReportingResult] =
    for
      _ <- logger.info(s"Reporting scan result ${result.scanId} to data center")
      _ <- result.events.traverse(repository.save)  // Save events locally
      reportResult <- client.reportScanResult(result)
      _ <- updateReportingStatus(reportResult)
    yield reportResult

  override def queueEvent[A <: SecurityEvent](event: A): F[Unit] =
    for
      _ <- repository.save(event)  // Always save locally first
      _ <- queue.offer(event)
        .handleErrorWith { error =>
          logger.warn(s"Failed to queue event, queue might be full: ${error.getMessage}")
        }
    yield ()

  override def startBackgroundReporting: F[Fiber[F, Throwable, Unit]] =
    val process = Stream.awakeEvery[F](reportingInterval)
      .evalMap(_ => processQueue)
      .handleErrorWith { error =>
        Stream.eval(logger.error(error)(s"Error in background reporting: ${error.getMessage}")) >>
          Stream.sleep[F](10.seconds) >>
          Stream.awakeEvery[F](reportingInterval).evalMap(_ => processQueue)
      }
      .compile
      .drain
      .foreverM

    process.start

  override def getStatus: F[ReportingServiceStatus] =
    for
      queueSize <- queue.size
      clientStatus <- client.getStatus
      lastSuccessfulReport <- lastSuccessfulReportRef.get
      failedReportsCount <- failedReportsCountRef.get
    yield ReportingServiceStatus(
      isConnected = clientStatus.connected,
      queueSize = queueSize,
      lastSuccessfulReport = lastSuccessfulReport,
      failedReportsCount = failedReportsCount,
      circuitBreakerOpen = clientStatus.circuitBreakerOpen,
      circuitBreakerHalfOpen = clientStatus.circuitBreakerHalfOpen,
      failureRate = clientStatus.failureRate
    )

  // Process the queue and send events in batches
  private def processQueue: F[Unit] =
    for
      _ <- logger.debug("Processing reporting queue")
      queueSize <- queue.size
      _ <- logger.debug(s"Current queue size: $queueSize")

      // Check connectivity before processing
      connected <- client.checkConnectivity
      _ <- if connected then
        processBatches
      else
        logger.warn("Not connected to data center, skipping report processing")
    yield ()

  // Process events in batches
  private def processBatches: F[Unit] =
    def loop(remaining: Int): F[Unit] =
      if remaining <= 0 then
        Async[F].unit
      else
        // Take a batch from the queue
        for
          events <- (0 until math.min(batchSize, remaining))
            .toList
            .traverse(_ => queue.tryTake)
            .map(_.flatten)

          _ <- if events.nonEmpty then
            logger.info(s"Sending batch of ${events.size} events to data center") >>
              client.reportEvents(events).flatMap {
                case ReportingResult.Success(reportId) =>
                  logger.info(s"Successfully reported batch, report ID: $reportId") >>
                    lastSuccessfulReportRef.set(Some(Instant.now())) >>
                    failedReportsCountRef.set(0)
                case ReportingResult.Failed(reason) =>
                  logger.warn(s"Failed to report batch: $reason") >>
                    failedReportsCountRef.update(_ + 1) >>
                    // Put events back in queue for retry if they weren't processed
                    events.traverse(event => queue.offer(event).attempt.void)
              }
          else
            Async[F].unit

          // Continue if we processed a full batch and there might be more
          newRemaining = remaining - events.size
          _ <- if events.size == batchSize then loop(newRemaining) else Async[F].unit
        yield ()

    // Get queue size and process up to 10 batches
    queue.size.flatMap(size => loop(math.min(size, batchSize * 10)))

  // Update reporting status based on result
  private def updateReportingStatus(result: ReportingResult): F[Unit] =
    result match
      case ReportingResult.Success(_) =>
        lastSuccessfulReportRef.set(Some(Instant.now())) >>
          failedReportsCountRef.set(0)
      case ReportingResult.Failed(_) =>
        failedReportsCountRef.update(_ + 1)
}

/** Status of the reporting service */
case class ReportingServiceStatus(
                                   isConnected: Boolean,
                                   queueSize: Int,
                                   lastSuccessfulReport: Option[Instant],
                                   failedReportsCount: Int,
                                   circuitBreakerOpen: Boolean,
                                   circuitBreakerHalfOpen: Boolean,
                                   failureRate: Float
                                 )