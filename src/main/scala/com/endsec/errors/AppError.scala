package com.endsec.errors

import cats.effect.Concurrent
import cats.syntax.all.*
import io.circe.{Encoder, Json}
import io.circe.syntax.*
import org.http4s.{Response, Status}
import org.http4s.circe.*
import org.typelevel.log4cats.Logger

import java.time.Instant
import java.util.UUID

/**
 * Core error types for the application
 */
sealed trait AppError extends Throwable {
  def id: UUID
  def message: String
  def cause: Option[Throwable]
  def timestamp: Instant
  def errorCode: String
  def details: Option[String]

  // Override methods from Throwable to use our message
  override def getMessage: String = message
  override def getCause: Throwable = cause.orNull
}

object AppError {
  /**
   * Error code prefixes by category
   */
  object ErrorCodePrefix {
    val General = "GEN"
    val Security = "SEC"
    val Network = "NET"
    val Virus = "VIR"
    val Vulnerability = "VUL"
    val Storage = "STR"
    val Api = "API"
    val Configuration = "CFG"
    val Authentication = "AUTH"
    val Validation = "VAL"
  }

  /**
   * Convert an exception to an AppError
   */
  def fromThrowable(
                     error: Throwable,
                     errorCode: String = ErrorCodePrefix.General + "-001",
                     details: Option[String] = None
                   ): AppError =
    error match {
      case appError: AppError => appError
      case _ =>
        GenericError(
          message = Option(error.getMessage).getOrElse("Unknown error"),
          cause = Some(error),
          errorCode = errorCode,
          details = details
        )
    }
}

/**
 * Generic error type for unknown or unexpected errors
 */
case class GenericError(
                         id: UUID = UUID.randomUUID(),
                         message: String,
                         cause: Option[Throwable] = None,
                         timestamp: Instant = Instant.now(),
                         errorCode: String = AppError.ErrorCodePrefix.General + "-001",
                         details: Option[String] = None
                       ) extends AppError

/**
 * Error during security scanning operations
 */
case class ScanError(
                      id: UUID = UUID.randomUUID(),
                      message: String,
                      cause: Option[Throwable] = None,
                      timestamp: Instant = Instant.now(),
                      errorCode: String = AppError.ErrorCodePrefix.Security + "-001",
                      scanType: String,
                      details: Option[String] = None
                    ) extends AppError

/**
 * Error during network monitoring operations
 */
case class NetworkError(
                         id: UUID = UUID.randomUUID(),
                         message: String,
                         cause: Option[Throwable] = None,
                         timestamp: Instant = Instant.now(),
                         errorCode: String = AppError.ErrorCodePrefix.Network + "-001",
                         networkResource: String,
                         details: Option[String] = None
                       ) extends AppError

/**
 * Error related to virus scanning operations
 */
case class VirusScanError(
                           id: UUID = UUID.randomUUID(),
                           message: String,
                           cause: Option[Throwable] = None,
                           timestamp: Instant = Instant.now(),
                           errorCode: String = AppError.ErrorCodePrefix.Virus + "-001",
                           scanTarget: String,
                           details: Option[String] = None
                         ) extends AppError

/**
 * Error related to vulnerability scanning operations
 */
case class VulnerabilityScanError(
                                   id: UUID = UUID.randomUUID(),
                                   message: String,
                                   cause: Option[Throwable] = None,
                                   timestamp: Instant = Instant.now(),
                                   errorCode: String = AppError.ErrorCodePrefix.Vulnerability + "-001",
                                   component: String,
                                   details: Option[String] = None
                                 ) extends AppError

/**
 * Error related to data storage operations
 */
case class StorageError(
                         id: UUID = UUID.randomUUID(),
                         message: String,
                         cause: Option[Throwable] = None,
                         timestamp: Instant = Instant.now(),
                         errorCode: String = AppError.ErrorCodePrefix.Storage + "-001",
                         operation: String,
                         details: Option[String] = None
                       ) extends AppError

/**
 * Error related to API requests or responses
 */
case class ApiError(
                     id: UUID = UUID.randomUUID(),
                     message: String,
                     cause: Option[Throwable] = None,
                     timestamp: Instant = Instant.now(),
                     errorCode: String = AppError.ErrorCodePrefix.Api + "-001",
                     statusCode: Int,
                     details: Option[String] = None
                   ) extends AppError

/**
 * Error related to configuration issues
 */
case class ConfigurationError(
                               id: UUID = UUID.randomUUID(),
                               message: String,
                               cause: Option[Throwable] = None,
                               timestamp: Instant = Instant.now(),
                               errorCode: String = AppError.ErrorCodePrefix.Configuration + "-001",
                               configKey: String,
                               details: Option[String] = None
                             ) extends AppError

/**
 * Error related to authentication or authorization
 */
case class AuthenticationError(
                                id: UUID = UUID.randomUUID(),
                                message: String,
                                cause: Option[Throwable] = None,
                                timestamp: Instant = Instant.now(),
                                errorCode: String = AppError.ErrorCodePrefix.Authentication + "-001",
                                details: Option[String] = None
                              ) extends AppError

/**
 * Error related to validation failures
 */
case class ValidationError(
                            id: UUID = UUID.randomUUID(),
                            message: String,
                            cause: Option[Throwable] = None,
                            timestamp: Instant = Instant.now(),
                            errorCode: String = AppError.ErrorCodePrefix.Validation + "-001",
                            validationFailures: List[String],
                            details: Option[String] = None
                          ) extends AppError

/**
 * Error response for API endpoints
 */
case class ErrorResponse(
                          id: UUID,
                          errorCode: String,
                          message: String,
                          timestamp: Instant,
                          details: Option[String],
                          path: Option[String] = None
                        )

object ErrorResponse {
  /**
   * Create an ErrorResponse from an AppError
   */
  def fromAppError(error: AppError, path: Option[String] = None): ErrorResponse =
    ErrorResponse(
      id = error.id,
      errorCode = error.errorCode,
      message = error.message,
      timestamp = error.timestamp,
      details = error.details,
      path = path
    )

  /**
   * Encoders for JSON serialization
   */
  given Encoder[ErrorResponse] = Encoder.instance { err =>
    Json.obj(
      "id" -> err.id.toString.asJson,
      "errorCode" -> err.errorCode.asJson,
      "message" -> err.message.asJson,
      "timestamp" -> err.timestamp.toString.asJson,
      "details" -> err.details.asJson,
      "path" -> err.path.asJson
    )
  }
}

/**
 * Error handling utilities for the application
 */
object ErrorHandler {
  /**
   * Handle errors in a consistent way for API responses
   */
  def handleError[F[_]: Concurrent: Logger](
                                             error: Throwable,
                                             requestPath: String = "unknown"
                                           ): F[Response[F]] = {
    val appError = error match {
      case e: AppError => e
      case _ => AppError.fromThrowable(error)
    }

    // Log the error with appropriate level
    val logAction = appError match {
      case _: ValidationError => Logger[F].info(s"Validation error: ${appError.message}")
      case _ => Logger[F].error(error)(s"Error in request: ${appError.message}")
    }

    // Map error types to appropriate HTTP status codes
    val status = appError match {
      case _: ValidationError => Status.BadRequest
      case _: AuthenticationError => Status.Unauthorized
      case _: ApiError => Status.fromInt(appError.asInstanceOf[ApiError].statusCode).getOrElse(Status.InternalServerError)
      case _: ConfigurationError => Status.InternalServerError
      case _ => Status.InternalServerError
    }

    // Create response with appropriate status and error details
    val errorResponse = ErrorResponse.fromAppError(appError, Some(requestPath))

    for {
      _ <- logAction
      response <- Response[F](status = status)
        .withEntity(errorResponse)(jsonEncoderOf[F, ErrorResponse])
        .pure[F]
    } yield response
  }

  /**
   * Convert a Throwable to an AppError
   */
  def convertError(error: Throwable): AppError = AppError.fromThrowable(error)
}