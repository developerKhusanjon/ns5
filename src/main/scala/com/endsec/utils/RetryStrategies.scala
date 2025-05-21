package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import fs2.Stream
import org.typelevel.log4cats.Logger

import scala.concurrent.duration.*
import io.github.resilience4j.retry.{Retry, RetryConfig}
import io.github.resilience4j.circuitbreaker.{CircuitBreaker, CircuitBreakerConfig}

import java.time.Duration
import java.util.function.Predicate

/**
 * Factory for creating standardized retry and circuit breaker configurations
 */
object RetryStrategies:
  /**
   * Create a standard retry configuration for network operations
   */
  def networkRetryConfig(
                          maxAttempts: Int = 3,
                          initialDelay: Duration = Duration.ofMillis(1000),
                          maxDelay: Duration = Duration.ofSeconds(10),
                          multiplier: Double = 2.0
                        ): RetryConfig =
    RetryConfig.custom()
      .maxAttempts(maxAttempts)
      .waitDuration(initialDelay)
      .retryExceptions(
        classOf[java.io.IOException],
        classOf[java.net.ConnectException],
        classOf[java.net.SocketTimeoutException],
        classOf[org.http4s.client.ConnectionFailure]
      )
      .ignoreExceptions(
        classOf[java.security.AccessControlException],
        classOf[java.lang.IllegalArgumentException]
      )
      .intervalFunction(IntervalFunction.ofExponentialBackoff(multiplier, initialDelay, maxDelay))
      .build()

  /**
   * Create a standard retry configuration for data operations
   */
  def dataRetryConfig(
                       maxAttempts: Int = 3,
                       initialDelay: Duration = Duration.ofMillis(500),
                       maxDelay: Duration = Duration.ofSeconds(5),
                       multiplier: Double = 1.5
                     ): RetryConfig =
    RetryConfig.custom()
      .maxAttempts(maxAttempts)
      .waitDuration(initialDelay)
      .retryExceptions(
        classOf[java.sql.SQLException],
        classOf[java.io.IOException]
      )
      .ignoreExceptions(
        classOf[java.sql.SQLSyntaxErrorException]
      )
      .intervalFunction(IntervalFunction.ofExponentialBackoff(multiplier, initialDelay, maxDelay))
      .build()

  /**
   * Create a standard circuit breaker configuration for service calls
   */
  def serviceCircuitBreakerConfig(
                                   failureRateThreshold: Float = 50.0f,
                                   waitDurationInOpenState: Duration = Duration.ofSeconds(30),
                                   ringBufferSizeInHalfOpenState: Int = 10,
                                   ringBufferSizeInClosedState: Int = 100,
                                   automaticTransitionFromOpenToHalfOpenEnabled: Boolean = true
                                 ): CircuitBreakerConfig =
    CircuitBreakerConfig.custom()
      .failureRateThreshold(failureRateThreshold)
      .waitDurationInOpenState(waitDurationInOpenState)
      .ringBufferSizeInHalfOpenState(ringBufferSizeInHalfOpenState)
      .ringBufferSizeInClosedState(ringBufferSizeInClosedState)
      .automaticTransitionFromOpenToHalfOpenEnabled(automaticTransitionFromOpenToHalfOpenEnabled)
      .build()

  /**
   * Create a standard circuit breaker configuration for critical services
   */
  def criticalServiceCircuitBreakerConfig(
                                           failureRateThreshold: Float = 25.0f,
                                           waitDurationInOpenState: Duration = Duration.ofSeconds(60),
                                           ringBufferSizeInHalfOpenState: Int = 5,
                                           ringBufferSizeInClosedState: Int = 50,
                                           automaticTransitionFromOpenToHalfOpenEnabled: Boolean = true
                                         ): CircuitBreakerConfig =
    CircuitBreakerConfig.custom()
      .failureRateThreshold(failureRateThreshold)
      .waitDurationInOpenState(waitDurationInOpenState)
      .ringBufferSizeInHalfOpenState(ringBufferSizeInHalfOpenState)
      .ringBufferSizeInClosedState(ringBufferSizeInClosedState)
      .automaticTransitionFromOpenToHalfOpenEnabled(automaticTransitionFromOpenToHalfOpenEnabled)
      .build()

  /**
   * Named retry strategies for use in the application
   */
  object RetryNames:
    val NetworkOperations = "network-operations"
    val DataOperations = "data-operations"
    val ApiCalls = "api-calls"
    val DataCenterReporting = "data-center-reporting"
    val FileOperations = "file-operations"

  /**
   * Named circuit breaker strategies for use in the application
   */
  object CircuitBreakerNames:
    val DataCenterClient = "data-center-client"
    val ApiServer = "api-server"
    val DatabaseAccess = "database-access"
    val FileSystem = "file-system"

/**
 * Helper function for creating interval functions for retry strategies
 */
object IntervalFunction:
  /**
   * Create an exponential backoff interval function
   */
  def ofExponentialBackoff(
                            multiplier: Double,
                            initialDelay: Duration,
                            maxDelay: Duration
                          ): (Long => Duration) = { attempt =>
    val delay = initialDelay.multipliedBy(Math.pow(multiplier, attempt - 1).toLong)
    if delay.compareTo(maxDelay) > 0 then maxDelay else delay
  }

  /**
   * Create a constant interval function
   */
  def ofConstant(delay: Duration): (Long => Duration) = _ => delay

  /**
   * Create a linear backoff interval function
   */
  def ofLinearBackoff(initialDelay: Duration, increment: Duration): (Long => Duration) = { attempt =>
    initialDelay.plus(increment.multipliedBy(attempt - 1))
  }

  /**
   * Create a randomized interval function with jitter
   */
  def ofRandomized(baseIntervalFn: Long => Duration, factor: Double = 0.5): (Long => Duration) = { attempt =>
    val baseInterval = baseIntervalFn(attempt)
    val randomizedDelta = (Math.random() * factor * 2 - factor) * baseInterval.toMillis
    Duration.ofMillis((baseInterval.toMillis + randomizedDelta).toLong)
  }