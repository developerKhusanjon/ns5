package com.endsec.api

import cats.effect.*
import cats.syntax.all.*
import org.http4s.*
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.circe.*
import org.http4s.headers.*
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import io.circe.syntax.*
import io.circe.generic.auto.*
import fs2.Stream
import io.github.resilience4j.retry.{Retry, RetryConfig}
import io.github.resilience4j.circuitbreaker.{CircuitBreaker, CircuitBreakerConfig}

import java.time.Duration
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.*
import com.endsec.domain.*
import com.endsec.services.ScanResult
import com.endsec.utils.{SystemInfo, ResilienceUtils}

/** Client for reporting security events to the data center */
trait DataCenterClient[F[_]]:
  /** Report a security event to the data center */
  def reportEvent[A <: SecurityEvent](event: A): F[ReportingResult]

  /** Report a batch of security events to the data center */
  def reportEvents[A <: SecurityEvent](events: List[A]): F[ReportingResult]

  /** Report scan results to the data center */
  def reportScanResult[A <: SecurityEvent](result: ScanResult[A]): F[ReportingResult]

  /** Check connectivity to the data center */
  def checkConnectivity: F[Boolean]

  /** Get the client status */
  def getStatus: F[DataCenterClientStatus]

object DataCenterClient:
  /** Create a new data center client */
  def make[F[_]: Async: Logger](
                                 baseUrl: String,
                                 apiKey: String,
                                 clientTimeout: FiniteDuration = 30.seconds,
                                 retryConfig: RetryConfig = RetryConfig.custom()
                                   .maxAttempts(3)
                                   .waitDuration(Duration.ofMillis(1000))
                                   .retryExceptions(classOf[java.io.IOException], classOf[org.http4s.client.ConnectionFailure])
                                   .build(),
                                 circuitBreakerConfig: CircuitBreakerConfig = CircuitBreakerConfig.custom()
                                   .failureRateThreshold(50)
                                   .waitDurationInOpenState(Duration.ofSeconds(30))
                                   .ringBufferSizeInHalfOpenState(10)
                                   .ringBufferSizeInClosedState(100)
                                   .build()
                               ): Resource[F, DataCenterClient[F]] =
    EmberClientBuilder.default[F]
      .withTimeout(clientTimeout)
      .build
      .map { httpClient =>
        val retry = Retry.of("dataCenterRetry", retryConfig)
        val circuitBreaker = CircuitBreaker.of("dataCenterCircuitBreaker", circuitBreakerConfig)

        new DataCenterClientImpl[F](
          httpClient,
          baseUrl,
          apiKey,
          retry,
          circuitBreaker
        )
      }

private class DataCenterClientImpl[F[_]: Async: Logger](
                                                         httpClient: Client[F],
                                                         baseUrl: String,
                                                         apiKey: String,
                                                         retry: Retry,
                                                         circuitBreaker: CircuitBreaker
                                                       ) extends DataCenterClient[F] with Http4sClientDsl[F]:

  private val logger = Slf4jLogger.getLogger[F]

  // JSON encoders for domain models
  private given EntityEncoder[F, ReportRequest] = jsonEncoderOf[F, ReportRequest]

  // Decoded return types
  private given EntityDecoder[F, ReportResponse] = jsonOf[F, ReportResponse]
  private given EntityDecoder[F, HealthResponse] = jsonOf[F, HealthResponse]

  override def reportEvent[A <: SecurityEvent](event: A): F[ReportingResult] =
    reportEvents(List(event))

  override def reportEvents[A <: SecurityEvent](events: List[A]): F[ReportingResult] =
    for
      hostInfo <- SystemInfo.getHostInfo[F]
      request = buildReportRequest(events, hostInfo)
      result <- executeWithResilience(sendReport(request))
    yield result

  override def reportScanResult[A <: SecurityEvent](result: ScanResult[A]): F[ReportingResult] =
    reportEvents(result.events)

  override def checkConnectivity: F[Boolean] =
    executeWithResilience(checkHealth().map(_.isRight)).recover { case _ => false }

  override def getStatus: F[DataCenterClientStatus] =
    for
      health <- checkHealth().attempt
      isOpen = circuitBreaker.getState.name() == "OPEN"
      halfOpen = circuitBreaker.getState.name() == "HALF_OPEN"
      failureRate = circuitBreaker.getMetrics.getFailureRate
    yield DataCenterClientStatus(
      connected = health.isRight,
      circuitBreakerOpen = isOpen,
      circuitBreakerHalfOpen = halfOpen,
      failureRate = failureRate
    )

  private def buildReportRequest[A <: SecurityEvent](events: List[A], hostInfo: HostInfo): ReportRequest =
    ReportRequest(
      timestamp = java.time.Instant.now(),
      hostInfo = hostInfo,
      events = events.map(event =>
        EventWrapper(
          id = event.id,
          timestamp = event.timestamp,
          severity = event.severity,
          source = event.source,
          details = event.details,
          eventType = event.getClass.getSimpleName,
          eventData = event.asJson
        )
      )
    )

  private def executeWithResilience[A](action: => F[A]): F[A] =
    ResilienceUtils.executeWithRetryAndCircuitBreaker(action, retry, circuitBreaker)

  private def checkHealth(): F[Either[Throwable, HealthResponse]] =
    val req = GET(
      Uri.unsafeFromString(s"$baseUrl/api/health"),
      Authorization(Credentials.Token(AuthScheme.Bearer, apiKey))
    )

    httpClient.expect[HealthResponse](req).attempt

  private def sendReport(request: ReportRequest): F[ReportingResult] =
    val req = POST(
      request,
      Uri.unsafeFromString(s"$baseUrl/api/reports"),
      Authorization(Credentials.Token(AuthScheme.Bearer, apiKey)),
      `Content-Type`(MediaType.application.json)
    )

    httpClient.expectOr[ReportResponse](req) { resp =>
      resp.status match
        case Status.Unauthorized =>
          Async[F].pure(ReportingResult.Failed("Unauthorized: Invalid API key"))
        case Status.BadRequest =>
          resp.as[String].map(body => ReportingResult.Failed(s"Bad request: $body"))
        case status if status.isServerError =>
          Async[F].pure(ReportingResult.Failed(s"Server error: ${status.code}"))
        case status =>
          Async[F].pure(ReportingResult.Failed(s"Unexpected status: ${status.code}"))
    }.attempt.flatMap {
      case Right(response) =>
        Async[F].pure(ReportingResult.Success(response.reportId))
      case Left(error) =>
        logger.error(error)(s"Failed to send report: ${error.getMessage}") >>
          Async[F].pure(ReportingResult.Failed(error.getMessage))
    }
}

/** Request model for sending reports to the data center */
case class ReportRequest(
                          timestamp: java.time.Instant,
                          hostInfo: HostInfo,
                          events: List[EventWrapper]
                        )

/** Wrapper for security events to include additional metadata */
case class EventWrapper(
                         id: java.util.UUID,
                         timestamp: java.time.Instant,
                         severity: Severity,
                         source: String,
                         details: String,
                         eventType: String,
                         eventData: io.circe.Json
                       )

/** Response model from the data center */
case class ReportResponse(
                           reportId: String,
                           timestamp: java.time.Instant,
                           eventsProcessed: Int,
                           message: String
                         )

/** Health check response */
case class HealthResponse(
                           status: String,
                           version: String,
                           timestamp: java.time.Instant
                         )

/** Status of the data center client */
case class DataCenterClientStatus(
                                   connected: Boolean,
                                   circuitBreakerOpen: Boolean,
                                   circuitBreakerHalfOpen: Boolean,
                                   failureRate: Float
                                 )

/** Result of a reporting operation */
sealed trait ReportingResult

object ReportingResult:
  case class Success(reportId: String) extends ReportingResult
  case class Failed(reason: String) extends ReportingResult