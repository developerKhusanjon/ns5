package com.endsec.utils

import cats.effect.*
import cats.syntax.all.*
import io.github.resilience4j.circuitbreaker.{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerRegistry}
import io.github.resilience4j.retry.{Retry, RetryConfig, RetryRegistry}
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger

import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.*

/**
 * Manages circuit breakers and retries for the application
 */
trait ResilienceManager[F[_]]:
  /**
   * Get or create a circuit breaker with the given name and configuration
   */
  def getOrCreateCircuitBreaker(name: String, config: CircuitBreakerConfig): F[CircuitBreaker]

  /**
   * Get or create a retry with the given name and configuration
   */
  def getOrCreateRetry(name: String, config: RetryConfig): F[Retry]

  /**
   * Get the current status of all circuit breakers
   */
  def getCircuitBreakerStatuses: F[Map[String, CircuitBreakerStatus]]

  /**
   * Execute an action with the specified circuit breaker and retry
   */
  def executeWithResilience[A](
                                action: => F[A],
                                circuitBreakerName: String,
                                retryName: String
                              ): F[A]

  /**
   * Reset a circuit breaker to its closed state
   */
  def resetCircuitBreaker(name: String): F[Unit]

object ResilienceManager:
  /**
   * Create a new ResilienceManager with default registries
   */
  def make[F[_]: Async: Logger]: F[ResilienceManager[F]] =
    for
      retryRegistry <- Sync[F].delay(RetryRegistry.ofDefaults())
      circuitBreakerRegistry <- Sync[F].delay(CircuitBreakerRegistry.ofDefaults())
    yield new ResilienceManagerImpl[F](retryRegistry, circuitBreakerRegistry)

/**
 * Implementation of ResilienceManager
 */
private class ResilienceManagerImpl[F[_]: Async: Logger](
                                                          retryRegistry: RetryRegistry,
                                                          circuitBreakerRegistry: CircuitBreakerRegistry
                                                        ) extends ResilienceManager[F]:
  private val logger = Slf4jLogger.getLogger[F]

  // Cache of created circuit breakers and retries for tracking
  private val circuitBreakers = new ConcurrentHashMap[String, CircuitBreaker]().asScala
  private val retries = new ConcurrentHashMap[String, Retry]().asScala

  override def getOrCreateCircuitBreaker(name: String, config: CircuitBreakerConfig): F[CircuitBreaker] =
    Sync[F].delay {
      val circuitBreaker = circuitBreakerRegistry.circuitBreaker(name, config)
      circuitBreakers.put(name, circuitBreaker)

      // Add event listeners for logging
      circuitBreaker.getEventPublisher().onStateTransition(event =>
        logger.info(s"Circuit breaker '$name' state changed: ${event.getStateTransition()}").unsafeRunSync()
      )
      circuitBreaker.getEventPublisher().onError(event =>
        logger.warn(s"Circuit breaker '$name' recorded error: ${event.getThrowable.getMessage}").unsafeRunSync()
      )

      circuitBreaker
    }

  override def getOrCreateRetry(name: String, config: RetryConfig): F[Retry] =
    Sync[F].delay {
      val retry = retryRegistry.retry(name, config)
      retries.put(name, retry)

      // Add event listeners for logging
      retry.getEventPublisher().onRetry(event =>
        logger.info(s"Retry '$name' attempt ${event.getNumberOfRetryAttempts()}: ${event.getLastThrowable.getMessage}").unsafeRunSync()
      )
      retry.getEventPublisher().onError(event =>
        logger.warn(s"Retry '$name' failed after ${event.getNumberOfRetryAttempts()} attempts: ${event.getLastThrowable.getMessage}").unsafeRunSync()
      )

      retry
    }

  override def getCircuitBreakerStatuses: F[Map[String, CircuitBreakerStatus]] =
    Sync[F].delay {
      circuitBreakers.map { case (name, cb) =>
        val metrics = cb.getMetrics()
        name -> CircuitBreakerStatus(
          name = name,
          state = cb.getState().name(),
          failureRate = metrics.getFailureRate(),
          numberOfBufferedCalls = metrics.getNumberOfBufferedCalls(),
          numberOfFailedCalls = metrics.getNumberOfFailedCalls(),
          numberOfSuccessfulCalls = metrics.getNumberOfSuccessfulCalls()
        )
      }.toMap
    }

  override def executeWithResilience[A](
                                         action: => F[A],
                                         circuitBreakerName: String,
                                         retryName: String
                                       ): F[A] =
    for
      cb <- getOrCreateCircuitBreaker(
        circuitBreakerName,
        RetryStrategies.serviceCircuitBreakerConfig()
      )
      retry <- getOrCreateRetry(
        retryName,
        RetryStrategies.networkRetryConfig()
      )
      result <- ResilienceUtils.executeWithRetryAndCircuitBreaker(action, retry, cb)
    yield result

  override def resetCircuitBreaker(name: String): F[Unit] =
    Sync[F].delay {
      circuitBreakers.get(name).foreach(_.reset())
    }

/**
 * Status information for a circuit breaker
 */
case class CircuitBreakerStatus(
                                 name: String,
                                 state: String,
                                 failureRate: Float,
                                 numberOfBufferedCalls: Int,
                                 numberOfFailedCalls: Int,
                                 numberOfSuccessfulCalls: Int
                               )