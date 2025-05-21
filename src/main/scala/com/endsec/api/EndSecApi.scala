package com.endsec.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.implicits.*
import org.http4s.server.Router
import org.http4s.server.middleware.{Logger => Http4sLogger, CORS}
import org.http4s.headers.*
import org.http4s.circe.*
import org.http4s.ember.server.EmberServerBuilder
import io.circe.generic.auto.*
import io.circe.syntax.*
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.*

import com.endsec.domain.*
import com.endsec.repositories.SecurityEventRepository
import com.endsec.services.*
import com.endsec.utils.SystemInfo

/** HTTP API for the EndSec application */
trait EndSecApi[F[_]]:
  /** Start the API server */
  def start(host: String, port: Int): F[Nothing]

object EndSecApi:
  /** Create a new API instance */
  def make[F[_]: Async: Logger](
                                 repository: SecurityEventRepository[F],
                                 virusScanService: VirusScanService[F],
                                 vulnerabilityScanService: VulnerabilityScanService[F],
                                 networkMonitorService: NetworkMonitorService[F],
                                 reportingService: Option[ReportingService[F]] = None
                               ): EndSecApi[F] =
    new EndSecApiImpl[F](
      repository,
      virusScanService,
      vulnerabilityScanService,
      networkMonitorService,
      reportingService
    )

private class EndSecApiImpl[F[_]: Async: Logger](
                                                  repository: SecurityEventRepository[F],
                                                  virusScanService: VirusScanService[F],
                                                  vulnerabilityScanService: VulnerabilityScanService[F],
                                                  networkMonitorService: NetworkMonitorService[F],
                                                  reportingService: Option[ReportingService[F]]
                                                ) extends EndSecApi[F]:

  private val dsl = new Http4sDsl[F] {}
  import dsl.*

  // JSON decoders and encoders
  private given EntityDecoder[F, ApiScanRequest] = jsonOf[F, ApiScanRequest]
  private given EntityDecoder[F, UUID] = jsonOf[F, UUID]

  // Health and status endpoints
  private val healthRoutes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "health" =>
      val response = ApiHealthResponse(
        status = "OK",
        version = "1.0.0",
        timestamp = Instant.now()
      )
      Ok(response.asJson)

    case GET -> Root / "status" =>
      for
        hostInfo <- SystemInfo.getHostInfo[F]
        networkStatus <- networkMonitorService.getCurrentStatus
        isMonitoring = networkStatus.isRunning
        reportingStatus <- reportingService.traverse(_.getStatus)
        response = ApiStatusResponse(
          host = hostInfo,
          networkMonitoring = isMonitoring,
          reportingConnected = reportingStatus.map(_.isConnected).getOrElse(false),
          reportingQueueSize = reportingStatus.map(_.queueSize).getOrElse(0),
          timestamp = Instant.now()
        )
        result <- Ok(response.asJson)
      yield result
  }

  // Security events endpoints
  private val eventsRoutes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "events" :? LimitQueryParamMatcher(limit) =>
      for
        events <- repository.getRecent[SecurityEvent](limit)
        result <- Ok(ApiEventsResponse(events = events, count = events.size).asJson)
      yield result

    case GET -> Root / "events" / "severity" / severity =>
      for
        sev <- parseSeverity(severity)
        events <- sev.fold(
          err => Async[F].pure(List.empty[SecurityEvent]),
          s => repository.getBySeverity[SecurityEvent](s)
        )
        result <- Ok(ApiEventsResponse(events = events, count = events.size).asJson)
      yield result

    case GET -> Root / "events" / UUIDVar(id) =>
      for
        event <- repository.getById[SecurityEvent](id)
        result <- event match
          case Some(e) => Ok(e.asJson)
          case None => NotFound(ApiError("Event not found", s"No event with ID $id").asJson)
      yield result
  }

  // Scan endpoints
  private val scanRoutes: HttpRoutes[F] = HttpRoutes.of[F] {
    case POST -> Root / "scan" / "virus" =>
      for
        result <- virusScanService.quickScan
        _ <- reportScanResult(result)
        response <- Ok(result.asJson)
      yield response

    case POST -> Root / "scan" / "vulnerability" =>
      for
        result <- vulnerabilityScanService.scanSystem()
        _ <- reportScanResult(result)
        response <- Ok(result.asJson)
      yield response

    case req @ POST -> Root / "scan" / "custom" =>
      for
        scanRequest <- req.as[ApiScanRequest]
        result <- scanRequest.scanType match
          case "virus" =>
            virusScanService.fullSystemScan
          case "vulnerability" =>
            vulnerabilityScanService.scanSystem()
          case _ =>
            Async[F].raiseError(new IllegalArgumentException(s"Unsupported scan type: ${scanRequest.scanType}"))
        _ <- reportScanResult(result)
        response <- Ok(result.asJson)
      yield response
  }

  // Network monitoring endpoints
  private val networkRoutes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "network" / "status" =>
      for
        status <- networkMonitorService.getCurrentStatus
        response <- Ok(status.asJson)
      yield response

    case POST -> Root / "network" / "start" =>
      for
        fiber <- networkMonitorService.startMonitoring
        status <- networkMonitorService.getCurrentStatus
        response <- Ok(status.asJson)
      yield response

    case POST -> Root / "network" / "stop" =>
      for
        status <- networkMonitorService.stopMonitoring
        response <- Ok(status.asJson)
      yield response
  }

  // Reporting endpoints
  private val reportingRoutes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "reporting" / "status" =>
      reportingService match
        case Some(service) =>
          for
            status <- service.getStatus
            response <- Ok(status.asJson)
          yield response
        case None =>
          NotFound(ApiError("Not Available", "Reporting service is not configured").asJson)
  }

  // Combine all routes
  private val apiRoutes: HttpRoutes[F] =
    healthRoutes <+> eventsRoutes <+> scanRoutes <+> networkRoutes <+> reportingRoutes

  // Add versioning and wrap in middleware
  private val routes: HttpRoutes[F] = Router(
    "/api/v1" -> apiRoutes
  )

  // Add logging middleware
  private val httpApp: HttpApp[F] = Http4sLogger.httpApp(
    logHeaders = true,
    logBody = false
  )(routes.orNotFound)

  // Add CORS middleware for browsers
  private val corsApp: HttpApp[F] = CORS.policy.withAllowOriginAll
    .withAllowCredentials(false)
    .withMaxAge(1.day)
    .apply(httpApp)

  // Reports a scan result via the reporting service if available
  private def reportScanResult[A <: SecurityEvent](result: ScanResult[A]): F[Unit] =
    reportingService match
      case Some(service) =>
        service.reportScanResult(result).attempt.void
      case None =>
        Async[F].unit

  // Helper for parsing severity from string
  private def parseSeverity(str: String): F[Either[String, Severity]] =
    Async[F].delay {
      try
        Right(Severity.valueOf(str.toUpperCase))
      catch
        case _: IllegalArgumentException =>
          Left(s"Invalid severity: $str")
    }

  // Query parameter extractor for limit
  private object LimitQueryParamMatcher extends OptionalQueryParamDecoderMatcher[Int]("limit") {
    def getLimit(opt: Option[Int]): Int = opt.getOrElse(10)
  }

  override def start(host: String, port: Int): F[Nothing] =
    val serverBuilder = EmberServerBuilder
      .default[F]
      .withHost(org.http4s.server.defaults.IPv4.fromString(host).get)
      .withPort(org.http4s.server.defaults.Port.fromInt(port).get)
      .withHttpApp(corsApp)
      .withErrorHandler { case error =>
        Logger[F].error(error)(s"Unhandled error in server: ${error.getMessage}") >>
          InternalServerError("Internal server error")
      }

    for
      _ <- Logger[F].info(s"Starting API server on $host:$port")
      _ <- serverBuilder.build.useForever
    yield sys.error("This should never happen - server terminated")  // This will never be reached
}

// Request and response models for the API
case class ApiScanRequest(
                           scanType: String,
                           options: Option[Map[String, String]] = None
                         )

case class ApiHealthResponse(
                              status: String,
                              version: String,
                              timestamp: Instant
                            )

case class ApiStatusResponse(
                              host: HostInfo,
                              networkMonitoring: Boolean,
                              reportingConnected: Boolean,
                              reportingQueueSize: Int,
                              timestamp: Instant
                            )

case class ApiEventsResponse(
                              events: List[SecurityEvent],
                              count: Int
                            )

case class ApiError(
                     error: String,
                     message: String
                   )