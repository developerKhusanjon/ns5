package com.endsec.utils

import cats.effect.{Async, Temporal}
import cats.syntax.all.*
import fs2.Stream
import io.github.resilience4j.retry.Retry
import io.github.resilience4j.circuitbreaker.CircuitBreaker
import org.typelevel.log4cats.Logger

import scala.concurrent.duration.*
import java.time.Duration
import scala.jdk.DurationConverters.*

/**
 * Utilities for resilience patterns in the application
 */
object ResilienceUtils:
  /**
   * Execute an action with retry and circuit breaker protection
   *
   * @param action The action to execute
   * @param retry The retry configuration
   * @param circuitBreaker The circuit breaker
   * @return The result of the action
   */
  def executeWithRetryAndCircuitBreaker[F[_]: Async: Logger, A](
                                                                 action: => F[A],
                                                                 retry: Retry,
                                                                 circuitBreaker: CircuitBreaker
                                                               ): F[A] =
    val decoratedAction = Retry.decorateCheckedSupplier(retry, () => action)
    val cbDecoratedAction = CircuitBreaker.decorateCheckedSupplier(
      circuitBreaker,
      decoratedAction
    )

    Async[F].defer {
      Async[F].blocking {
        try
          Async[F].fromCompletableFuture(
            Async[F].delay(cbDecoratedAction.get().unsafeToCompletableFuture())
          )
        catch
          case e: Exception =>
            Logger[F].error(e)(s"Resilience operation failed: ${e.getMessage}") >>
              Async[F].raiseError(e)
      }.flatten
    }

  /**
   * Create a rate limiter for operations
   *
   * @param maxRate Maximum number of operations per time unit
   * @param timeUnit Time unit for the rate
   * @return A function that will execute actions at the specified rate
   */
  def rateLimiter[F[_]: Temporal, A](
                                      maxRate: Int,
                                      timeUnit: Duration = Duration.ofSeconds(1)
                                    ): F[A] => Stream[F, A] =
    val interval = timeUnit.toMillis.millis / maxRate

    action => Stream.eval(action).metered(interval)

  /**
   * Exponential backoff retry strategy
   *
   * @param maxRetries Maximum number of retries
   * @param initialDelay Initial delay before first retry
   * @param maxDelay Maximum delay between retries
   * @return A stream of delays to use for retries
   */
  def exponentialBackoff[F[_]](
                                maxRetries: Int,
                                initialDelay: FiniteDuration = 100.millis,
                                maxDelay: FiniteDuration = 30.seconds
                              ): Stream[F, FiniteDuration] =
    Stream.iterate(initialDelay)(prev => (prev * 2).min(maxDelay))
      .take(maxRetries)

  /**
   * Execute an action with exponential backoff retries
   *
   * @param action The action to execute
   * @param maxRetries Maximum number of retries
   * @param initialDelay Initial delay before first retry
   * @param maxDelay Maximum delay between retries
   * @param shouldRetry Predicate to determine if an error should trigger a retry
   * @return The result of the action, or the last error if all retries fail
   */
  def retryWithBackoff[F[_]: Async: Logger, A](
                                                action: => F[A],
                                                maxRetries: Int = 5,
                                                initialDelay: FiniteDuration = 100.millis,
                                                maxDelay: FiniteDuration = 30.seconds,
                                                shouldRetry: Throwable => Boolean = _ => true
                                              ): F[A] =
    // Try the action first
    action.handleErrorWith { error =>
      if maxRetries > 0 && shouldRetry(error) then
        for
          _ <- Logger[F].warn(s"Operation failed, retrying in $initialDelay: ${error.getMessage}")
          _ <- Temporal[F].sleep(initialDelay)
          // Recursive call with reduced retry count and increased delay
          nextDelay = (initialDelay * 2).min(maxDelay)
          result <- retryWithBackoff(
            action,
            maxRetries - 1,
            nextDelay,
            maxDelay,
            shouldRetry
          )
        yield result
      else
        Logger[F].error(error)(s"Operation failed after retries: ${error.getMessage}") >>
          Async[F].raiseError(error)
    }

  /**
   * Timeout pattern for operations that might hang
   *
   * @param action The action to execute
   * @param timeout Maximum time to wait for the action to complete
   * @param timeoutHandler Handler for timeout situations
   * @return The result of the action, or the result of the timeout handler
   */
  def withTimeout[F[_]: Async: Temporal, A](
                                             action: F[A],
                                             timeout: FiniteDuration,
                                             timeoutHandler: => F[A] = Async[F].raiseError(new java.util.concurrent.TimeoutException("Operation timed out"))
                                           ): F[A] =
    Temporal[F].timeoutTo(action, timeout, timeoutHandler)